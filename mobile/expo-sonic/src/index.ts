/**
 * @vouch-protocol-official/expo-sonic
 *
 * Expo native module that bridges React Native to the Vouch Sonic Core
 * (Rust, via UniFFI) for real on-device audio-watermark detection and
 * Ed25519 signature verification.
 *
 * The native module is registered under the name `VouchSonicCore` and is
 * reached with expo-modules-core's `requireOptionalNativeModule`, so it is
 * New-Architecture compatible (Expo SDK 54 / RN 0.81+).
 *
 * Drop-in usage (replaces a hand-rolled NativeModules.VouchSonicCore bridge):
 *
 *   import { SonicListener, isSonicAvailable } from '@vouch-protocol-official/expo-sonic';
 *   const listener = new SonicListener({ sampleRate: 16000 });
 *   await listener.start({ onWatermarkDetected: r => console.log(r) });
 */

import type { EventSubscription } from 'expo-modules-core';

import VouchSonicCore from './VouchSonicCoreModule';
import type {
  ListenerState,
  SonicConfig,
  SonicEventHandlers,
  VerificationResult,
  WatermarkResult,
} from './VouchSonicCore.types';

export * from './VouchSonicCore.types';
export { VouchSonicCore };

/** True when the native Sonic Core is linked (i.e. NOT a bare Expo Go run). */
export function isSonicAvailable(): boolean {
  return VouchSonicCore != null;
}

/** Engine version string, or a mock marker when the native module is absent. */
export async function getSonicVersion(): Promise<string> {
  if (!VouchSonicCore) return 'mock-unavailable';
  return VouchSonicCore.getVersion();
}

/**
 * Verify an Ed25519 signature via the Rust SignatureVerifier. Inputs are
 * base64-encoded. Throws if the native module is not linked.
 */
export async function verifySignature(
  messageB64: string,
  signatureB64: string,
  publicKeyB64: string
): Promise<VerificationResult> {
  if (!VouchSonicCore) {
    throw new Error('VouchSonicCore native module is not available in this runtime.');
  }
  return VouchSonicCore.verifySignature(messageB64, signatureB64, publicKeyB64);
}

const DEFAULT_CONFIG: SonicConfig = {
  sampleRate: 16000,
  frameSizeMs: 50,
  detectionThreshold: 0.5,
  spreadingFactor: 100,
  enableChirpSync: true,
};

/**
 * Real-time watermark listener backed by the native Rust Sonic Core.
 *
 * This mirrors the API surface previously stubbed in the mobile host app's
 * SonicBridge so it can be adopted as a drop-in. Audio *capture* (e.g. via
 * expo-av) remains the app's responsibility; feed PCM in with
 * `processBuffer` / `processSamples`, or call `start()` to let the native
 * listener stream (where supported).
 */
export class SonicListener {
  private listenerId: string | null = null;
  private config: SonicConfig;
  private handlers: SonicEventHandlers = {};
  private subscriptions: EventSubscription[] = [];
  private _isListening = false;

  constructor(config?: Partial<SonicConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Whether the native Sonic Core is linked in this build. */
  static get isAvailable(): boolean {
    return isSonicAvailable();
  }

  private async ensureInitialized(): Promise<void> {
    if (this.listenerId) return;
    if (!VouchSonicCore) {
      throw new Error(
        'VouchSonicCore native module is not available (e.g. running in Expo Go). ' +
          'Build a dev client or production build that includes @vouch-protocol-official/expo-sonic.'
      );
    }
    this.listenerId = await VouchSonicCore.createListener(this.config);
    this.attachEvents();
  }

  private attachEvents(): void {
    if (!VouchSonicCore || !this.listenerId) return;
    const id = this.listenerId;
    this.subscriptions = [
      VouchSonicCore.addListener('onWatermark', (p) => {
        if (p.listenerId === id) this.handlers.onWatermarkDetected?.(p.result);
      }),
      VouchSonicCore.addListener('onAudioLevel', (p) => {
        if (p.listenerId === id) this.handlers.onAudioLevelChanged?.(p.levelDb);
      }),
      VouchSonicCore.addListener('onError', (p) => {
        if (p.listenerId === id) this.handlers.onError?.(p.message);
      }),
      VouchSonicCore.addListener('onStateChange', (p) => {
        if (p.listenerId === id) this.handlers.onStateChanged?.(p.state);
      }),
    ];
  }

  async start(handlers?: SonicEventHandlers): Promise<void> {
    await this.ensureInitialized();
    if (handlers) this.handlers = handlers;
    await VouchSonicCore!.startListening(this.listenerId!);
    this._isListening = true;
    this.handlers.onStateChanged?.('Listening');
  }

  async stop(): Promise<void> {
    if (!VouchSonicCore || !this.listenerId) return;
    await VouchSonicCore.stopListening(this.listenerId);
    this._isListening = false;
    this.handlers.onStateChanged?.('Idle');
  }

  async processBuffer(pcmDataB64: string): Promise<WatermarkResult> {
    await this.ensureInitialized();
    return VouchSonicCore!.processBuffer(this.listenerId!, pcmDataB64);
  }

  async processSamples(samples: number[]): Promise<WatermarkResult> {
    await this.ensureInitialized();
    return VouchSonicCore!.processSamples(this.listenerId!, samples);
  }

  async setDetectionThreshold(threshold: number): Promise<void> {
    this.config.detectionThreshold = threshold;
    if (VouchSonicCore && this.listenerId) {
      await VouchSonicCore.setDetectionThreshold(this.listenerId, threshold);
    }
  }

  async getState(): Promise<ListenerState> {
    if (!VouchSonicCore || !this.listenerId) return 'Idle';
    return VouchSonicCore.getState(this.listenerId);
  }

  getConfig(): SonicConfig {
    return { ...this.config };
  }

  get isListening(): boolean {
    return this._isListening;
  }

  dispose(): void {
    this.subscriptions.forEach((s) => s.remove());
    this.subscriptions = [];
    const id = this.listenerId;
    this.listenerId = null;
    this._isListening = false;
    if (VouchSonicCore && id) {
      VouchSonicCore.disposeListener(id).catch(() => {});
    }
  }
}

export default SonicListener;
