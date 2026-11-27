import assert from 'node:assert/strict';
import { test } from 'node:test';

import { classify, handle, jsonldSource } from '../worker.js';

const SITE = 'https://vouch-protocol.org';

/** A stand-in for fetch that records every call and answers from a table. */
function siteStub(table = {}) {
    const calls = [];
    const impl = async (input, init = {}) => {
        const url = typeof input === 'string' ? input : input.url;
        calls.push({ url, init, passedRequest: typeof input !== 'string' });
        const entry = table[url];
        if (!entry) return new Response('missing', { status: 404 });
        return typeof entry === 'function' ? entry() : entry;
    };
    return { impl, calls };
}

function get(path, init = {}) {
    return new Request(`https://vouch-protocol.com${path}`, init);
}

const DID_DOC = JSON.stringify({ id: 'did:web:vouch-protocol.com' });

function didResponse() {
    return new Response(DID_DOC, {
        status: 200,
        headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'max-age=600',
            'set-cookie': 'tracker=1',
            server: 'GitHub.com',
        },
    });
}

test('pages redirect permanently to the same path and query on the site', async () => {
    const { impl, calls } = siteStub();
    for (const path of ['/', '/faq/', '/privacy.html', '/c/someone/320', '/blog/a-post/?utm=x&y=1', '/?ask=open']) {
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 301, path);
        assert.equal(response.headers.get('location'), SITE + path, path);
    }
    assert.equal(calls.length, 0, 'a redirect never contacts the site');
});

test('a redirect can never leave the site', async () => {
    const { impl } = siteStub();
    const hostile = ['//evil.example/', '/\\evil.example/', '//evil.example/contexts/v1', '/%2F%2Fevil.example', '/@evil.example/'];
    for (const path of hostile) {
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 301, path);
        const location = new URL(response.headers.get('location'));
        assert.equal(location.origin, SITE, path);
    }
});

test('did:web documents are served from the .com address', async () => {
    const paths = ['/.well-known/did.json', '/contributors/did.json', '/conformance/did.json', '/adopters/did.json'];
    for (const path of paths) {
        const { impl, calls } = siteStub({ [SITE + path]: didResponse });
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 200, path);
        assert.equal(await response.text(), DID_DOC, path);
        assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8');
        assert.equal(response.headers.get('cache-control'), 'max-age=600');
        assert.equal(response.headers.get('location'), null);
        assert.deepEqual(
            calls.map((call) => call.url),
            [SITE + path],
        );
    }
});

test('only the listed headers come back from the site', async () => {
    const { impl } = siteStub({ [`${SITE}/.well-known/did.json`]: didResponse });
    const response = await handle(get('/.well-known/did.json'), {}, impl);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('server'), null);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
});

test('the query, cookies and credentials of the caller are not sent to the site', async () => {
    const { impl, calls } = siteStub({ [`${SITE}/schemas/v1`]: () => new Response('{}', { status: 200 }) });
    const request = get('/schemas/v1?x=1', { headers: { cookie: 'session=secret', authorization: 'Bearer secret' } });
    const response = await handle(request, {}, impl);
    assert.equal(response.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `${SITE}/schemas/v1`);
    assert.equal(calls[0].passedRequest, false);
    assert.deepEqual(calls[0].init.headers, { accept: '*/*' });
    assert.equal(calls[0].init.redirect, 'manual');
});

test('context, vocabulary, status and tool files count as identifiers', () => {
    const identifiers = [
        '/contexts/v1',
        '/contexts/conformance/v1',
        '/schemas/pad-018/v1',
        '/ns/v1',
        '/credentials/status/1.json',
        '/attribution/v1',
        '/covenants/v1',
        '/funding.json',
        '/install.sh',
        '/.well-known/did.json',
        '/anything/did.json',
    ];
    for (const path of identifiers) assert.equal(classify(path), 'identifier', path);
    for (const path of ['/', '/contexts', '/faq/', '/did.json.html', '/funding.json/x', '/install.sh.bak', '/blog/contexts/']) {
        assert.equal(classify(path), 'page', path);
    }
});

test('a same-site redirect is followed and still answers 200 on .com', async () => {
    const { impl, calls } = siteStub({
        [`${SITE}/schemas/v1`]: () => new Response(null, { status: 301, headers: { location: '/schemas/v1/' } }),
        [`${SITE}/schemas/v1/`]: () =>
            new Response('{"$id":"x"}', { status: 200, headers: { 'content-type': 'application/schema+json' } }),
    });
    const response = await handle(get('/schemas/v1'), {}, impl);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '{"$id":"x"}');
    assert.equal(response.headers.get('content-type'), 'application/schema+json');
    assert.equal(calls.length, 2);
});

const CONTEXT_DOC = '{"@context":{"@version":1.1}}';

function jsonldFile(contentType = 'application/ld+json') {
    return () => new Response(CONTEXT_DOC, { status: 200, headers: { 'content-type': contentType, 'cache-control': 'max-age=600' } });
}

test('a context or vocabulary URL is answered from its .jsonld file as JSON-LD', async () => {
    const cases = {
        '/contexts/v1': '/contexts/v1.jsonld',
        '/ns/v1': '/ns/v1.jsonld',
        '/contexts/conformance/v1': '/contexts/conformance/v1.jsonld',
        '/contexts/v1.1': '/contexts/v1.1.jsonld',
    };
    for (const [path, file] of Object.entries(cases)) {
        assert.equal(jsonldSource(path), file, path);
        const { impl, calls } = siteStub({ [SITE + file]: jsonldFile() });
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 200, path);
        assert.equal(await response.text(), CONTEXT_DOC, path);
        assert.equal(response.headers.get('content-type'), 'application/ld+json', path);
        assert.equal(response.headers.get('access-control-allow-origin'), '*', path);
        assert.equal(response.headers.get('x-content-type-options'), 'nosniff', path);
        assert.equal(response.headers.get('cache-control'), 'max-age=600', path);
        assert.equal(response.headers.get('location'), null, path);
        assert.deepEqual(
            calls.map((call) => call.url),
            [SITE + file],
            path,
        );
    }
});

test('a context is labelled JSON-LD whatever type the site gives the file', async () => {
    for (const siteType of ['application/octet-stream', 'text/plain; charset=utf-8', 'text/html']) {
        const { impl } = siteStub({ [`${SITE}/contexts/v1.jsonld`]: jsonldFile(siteType) });
        const response = await handle(get('/contexts/v1'), {}, impl);
        assert.equal(response.headers.get('content-type'), 'application/ld+json', siteType);
    }
});

test('a path that already names a JSON file is fetched as it is', async () => {
    for (const path of ['/contexts/v1.jsonld', '/contexts/v1.json', '/ns/v1.jsonld']) {
        assert.equal(jsonldSource(path), null, path);
        const { impl, calls } = siteStub({ [SITE + path]: jsonldFile('application/json') });
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 200, path);
        assert.equal(response.headers.get('content-type'), 'application/json', path);
        assert.deepEqual(
            calls.map((call) => call.url),
            [SITE + path],
            path,
        );
    }
});

test('only context and vocabulary paths get the .jsonld mapping', () => {
    const unmapped = ['/schemas/v1', '/credentials/status/1.json', '/.well-known/did.json', '/contexts/', '/contexts/v1/', '/faq/', '/contexts', '/ns'];
    for (const path of unmapped) assert.equal(jsonldSource(path), null, path);
});

test('a missing context is a plain 404 after one request, with no probing of other paths', async () => {
    const { impl, calls } = siteStub();
    const response = await handle(get('/contexts/v9'), {}, impl);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('location'), null);
    assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.deepEqual(
        calls.map((call) => call.url),
        [`${SITE}/contexts/v9.jsonld`],
    );
});

test('a context request carries nothing from the caller and accepts GET and HEAD only', async () => {
    const table = { [`${SITE}/contexts/v1.jsonld`]: jsonldFile() };
    const { impl, calls } = siteStub(table);
    const request = get('/contexts/v1?cache=bust', { headers: { cookie: 'session=secret', authorization: 'Bearer secret' } });
    assert.equal((await handle(request, {}, impl)).status, 200);
    assert.equal(calls[0].url, `${SITE}/contexts/v1.jsonld`);
    assert.deepEqual(calls[0].init.headers, { accept: '*/*' });

    const head = siteStub(table);
    const headResponse = await handle(get('/contexts/v1', { method: 'HEAD' }), {}, head.impl);
    assert.equal(headResponse.status, 200);
    assert.equal(headResponse.headers.get('content-type'), 'application/ld+json');
    assert.equal(await headResponse.text(), '');

    const post = siteStub(table);
    assert.equal((await handle(get('/contexts/v1', { method: 'POST' }), {}, post.impl)).status, 405);
    assert.equal(post.calls.length, 0);
});

test('a hostile context path cannot reach another host or climb out of the prefix', async () => {
    const hostile = ['/contexts//evil.example/x', '/contexts/@evil.example', '/contexts/%2F%2Fevil.example', '/contexts/\\evil.example', '/ns//evil.example'];
    for (const path of hostile) {
        const { impl, calls } = siteStub();
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 404, path);
        for (const call of calls) assert.equal(new URL(call.url).origin, SITE, path);
    }
    // Dot segments are resolved before the path is classified, so these are
    // ordinary page requests and never reach the JSON-LD mapping.
    for (const path of ['/contexts/../faq', '/contexts/%2e%2e/faq', '/ns/../../faq']) {
        const { impl, calls } = siteStub();
        const response = await handle(get(path), {}, impl);
        assert.equal(response.status, 301, path);
        assert.equal(response.headers.get('location'), `${SITE}/faq`, path);
        assert.equal(calls.length, 0, path);
    }
});

test('a redirect from the site for a context is refused when it leaves the site', async () => {
    const { impl, calls } = siteStub({
        [`${SITE}/contexts/v1.jsonld`]: () => new Response(null, { status: 302, headers: { location: 'https://evil.example/v1.jsonld' } }),
    });
    const response = await handle(get('/contexts/v1'), {}, impl);
    assert.equal(response.status, 502);
    assert.deepEqual(
        calls.map((call) => call.url),
        [`${SITE}/contexts/v1.jsonld`],
    );
});

test('a redirect to another host is refused and that host is never contacted', async () => {
    for (const location of ['https://evil.example/did.json', '//evil.example/did.json', 'http://vouch-protocol.org/did.json']) {
        const { impl, calls } = siteStub({
            [`${SITE}/.well-known/did.json`]: () => new Response(null, { status: 302, headers: { location } }),
        });
        const response = await handle(get('/.well-known/did.json'), {}, impl);
        assert.equal(response.status, 502, location);
        assert.deepEqual(
            calls.map((call) => call.url),
            [`${SITE}/.well-known/did.json`],
            location,
        );
    }
});

test('a redirect loop on the site ends with an error', async () => {
    const { impl, calls } = siteStub({
        [`${SITE}/schemas/v1`]: () => new Response(null, { status: 301, headers: { location: '/schemas/v1' } }),
    });
    const response = await handle(get('/schemas/v1'), {}, impl);
    assert.equal(response.status, 502);
    assert.equal(calls.length, 3);
});

test('a missing identifier is a plain 404, not a redirect and not the site page', async () => {
    const { impl } = siteStub();
    const response = await handle(get('/contexts/does-not-exist'), {}, impl);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('location'), null);
    assert.equal(await response.text(), 'Not found\n');
});

test('site errors and unexpected statuses surface as 502', async () => {
    const failing = siteStub({ [`${SITE}/.well-known/did.json`]: () => new Response('boom', { status: 500 }) });
    assert.equal((await handle(get('/.well-known/did.json'), {}, failing.impl)).status, 502);

    const partial = siteStub({ [`${SITE}/.well-known/did.json`]: () => new Response('part', { status: 206 }) });
    assert.equal((await handle(get('/.well-known/did.json'), {}, partial.impl)).status, 502);

    const throwing = async () => {
        throw new Error('network down');
    };
    assert.equal((await handle(get('/.well-known/did.json'), {}, throwing)).status, 502);
});

test('identifiers accept GET and HEAD only', async () => {
    const table = { [`${SITE}/.well-known/did.json`]: didResponse };
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
        const { impl, calls } = siteStub(table);
        const response = await handle(get('/.well-known/did.json', { method }), {}, impl);
        assert.equal(response.status, 405, method);
        assert.equal(response.headers.get('allow'), 'GET, HEAD');
        assert.equal(calls.length, 0, method);
    }
    const { impl, calls } = siteStub(table);
    const head = await handle(get('/.well-known/did.json', { method: 'HEAD' }), {}, impl);
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    assert.equal(calls[0].init.method, 'HEAD');
});

test('paths owned by the other Workers go to the origin untouched', async () => {
    for (const path of ['/v/abc12345', '/api/v1/c2pa/crl', '/.well-known/c2pa-trust-list']) {
        assert.equal(classify(path), 'other', path);
        const calls = [];
        const impl = async (input) => {
            calls.push(input);
            return new Response('from origin', { status: 200 });
        };
        const request = get(path);
        const response = await handle(request, {}, impl);
        assert.equal(await response.text(), 'from origin', path);
        assert.equal(calls.length, 1);
        assert.equal(calls[0], request, 'the original request is passed through');
    }
});

test('the site origin can be configured and must be a plain https origin', async () => {
    const { impl } = siteStub();
    const response = await handle(get('/faq/'), { SITE_ORIGIN: 'https://staging.example' }, impl);
    assert.equal(response.headers.get('location'), 'https://staging.example/faq/');

    for (const bad of ['http://vouch-protocol.org', 'https://vouch-protocol.org/path', 'https://user@vouch-protocol.org']) {
        await assert.rejects(() => handle(get('/faq/'), { SITE_ORIGIN: bad }, impl), /plain https origin/, bad);
    }
});
