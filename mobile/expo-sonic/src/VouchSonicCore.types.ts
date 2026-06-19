/**
 * Shared types for @vouch-protocol-official/expo-sonic.
 *
 * Field names are camelCase to match the JS conventions used by consumers
 * (e.g. the mobile host app's SonicBridge). The native bridge maps the UniFFI
 * snake_case records onto these camelCase shapes.
 */

export interface SonicConfig {
  /** Target sample rate in Hz (default 16000). */
  sampleRate: number;
  /** Frame size in milliseconds (default 50). */
  frameSizeMs: number;
  /** Detection confidence threshold 0.0-1.0 (default 0.5). */
  detectionThreshold: number;
  /** Spread-spectrum factor (default 100). */
  spreadingFactor: number;
  /** Enable chirp synchronization (default true). */
  enableChirpSync: boolean;
}

export interface WatermarkResult {
  detected: boolean;
  confidence: number;
  signerDid: string | null;
  timestamp: number | null;
  payloadHash: string | null;
  covenantJson: string | null;
  audioQuality: number;
  /** "spread_spectrum" | "chirp" | "mock" | ... */
  detectionMethod: string;
}

export interface VerificationResult {
  valid: boolean;
  signerDid: string | null;
  errorMessage: string | null;
}

export type ListenerState = 'Idle' | 'Listening' | 'Processing' | 'Error';

export interface SonicEventHandlers {
  onWatermarkDetected?: (result: WatermarkResult) => void;
  onAudioLevelChanged?: (levelDb: number) => void;
  onError?: (message: string) => void;
  onStateChanged?: (state: ListenerState) => void;
}

// ---- Native event payloads (carry the listenerId so the JS layer can route) -

export interface WatermarkEventPayload {
  listenerId: string;
  result: WatermarkResult;
}
export interface AudioLevelEventPayload {
  listenerId: string;
  levelDb: number;
}
export interface ErrorEventPayload {
  listenerId: string;
  message: string;
}
export interface StateEventPayload {
  listenerId: string;
  state: ListenerState;
}

export type VouchSonicCoreModuleEvents = {
  onWatermark: (payload: WatermarkEventPayload) => void;
  onAudioLevel: (payload: AudioLevelEventPayload) => void;
  onError: (payload: ErrorEventPayload) => void;
  onStateChange: (payload: StateEventPayload) => void;
};

/**
 * The flat, handle-based native module surface exposed under the name
 * "VouchSonicCore". A listenerId string identifies a native SonicListener
 * instance held on the native side.
 */
export interface VouchSonicCoreNativeModule {
  getVersion(): Promise<string>;
  createListener(config: SonicConfig): Promise<string>;
  startListening(listenerId: string): Promise<void>;
  stopListening(listenerId: string): Promise<void>;
  /** pcmData is base64-encoded 16-bit LE mono PCM. */
  processBuffer(listenerId: string, pcmData: string): Promise<WatermarkResult>;
  processSamples(listenerId: string, samples: number[]): Promise<WatermarkResult>;
  getState(listenerId: string): Promise<ListenerState>;
  isListening(listenerId: string): Promise<boolean>;
  setDetectionThreshold(listenerId: string, threshold: number): Promise<void>;
  disposeListener(listenerId: string): Promise<void>;
  /** Ed25519 verification via the Rust SignatureVerifier. Inputs are base64. */
  verifySignature(
    messageB64: string,
    signatureB64: string,
    publicKeyB64: string
  ): Promise<VerificationResult>;
}
