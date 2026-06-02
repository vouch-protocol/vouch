import { NativeModule, requireOptionalNativeModule } from 'expo-modules-core';

import type {
  VouchSonicCoreModuleEvents,
  VouchSonicCoreNativeModule,
} from './VouchSonicCore.types';

declare class VouchSonicCoreModule
  extends NativeModule<VouchSonicCoreModuleEvents>
  implements VouchSonicCoreNativeModule
{
  getVersion(): Promise<string>;
  createListener(config: import('./VouchSonicCore.types').SonicConfig): Promise<string>;
  startListening(listenerId: string): Promise<void>;
  stopListening(listenerId: string): Promise<void>;
  processBuffer(
    listenerId: string,
    pcmData: string
  ): Promise<import('./VouchSonicCore.types').WatermarkResult>;
  processSamples(
    listenerId: string,
    samples: number[]
  ): Promise<import('./VouchSonicCore.types').WatermarkResult>;
  getState(listenerId: string): Promise<import('./VouchSonicCore.types').ListenerState>;
  isListening(listenerId: string): Promise<boolean>;
  setDetectionThreshold(listenerId: string, threshold: number): Promise<void>;
  disposeListener(listenerId: string): Promise<void>;
  verifySignature(
    messageB64: string,
    signatureB64: string,
    publicKeyB64: string
  ): Promise<import('./VouchSonicCore.types').VerificationResult>;
}

// Loads the native module registered under the name "VouchSonicCore", or
// returns null when it is not linked (e.g. inside Expo Go, where no custom
// native code is present). Callers should guard with `isSonicAvailable`.
const VouchSonicCore = requireOptionalNativeModule<VouchSonicCoreModule>('VouchSonicCore');

export default VouchSonicCore;
