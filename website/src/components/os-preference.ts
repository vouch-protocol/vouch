'use client';

import { useEffect, useState } from 'react';

/**
 * Shared OS preference for command code blocks. One source of truth used by both
 * the global OSSwitcher in the nav and every OSCodeBlock on the page. Set it once
 * (anywhere) and every OS-aware block follows; the choice persists to
 * localStorage so it carries across pages and visits.
 *
 * macOS and Linux share a value ("unix") because their command text is identical.
 */

export type OS = 'unix' | 'windows';
const STORAGE_KEY = 'vouch-os-pref';

let current: OS = 'unix';
const listeners = new Set<(os: OS) => void>();

export function getOSPreference(): OS {
  return current;
}

export function setOSPreference(os: OS): void {
  current = os;
  try {
    localStorage.setItem(STORAGE_KEY, os);
  } catch {
    /* storage unavailable */
  }
  listeners.forEach((fn) => fn(os));
}

/**
 * Subscribe to the shared OS preference. Returns the current OS and a setter
 * that updates every subscriber on the page and persists the choice. Hydrates
 * from localStorage on mount (after hydration, so it does not cause a mismatch).
 */
export function useOSPreference(): [OS, (os: OS) => void] {
  const [os, setOs] = useState<OS>(current);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) as OS | null;
      if (stored === 'unix' || stored === 'windows') {
        current = stored;
      }
    } catch {
      /* storage unavailable */
    }
    setOs(current);
    const listener = (next: OS) => setOs(next);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  return [os, setOSPreference];
}
