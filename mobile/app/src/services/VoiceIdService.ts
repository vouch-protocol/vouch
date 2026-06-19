/**
 * VoiceIdService - Voice Biometric Enrollment & Verification for Mobile
 *
 * Records audio on-device, sends the base64 WAV to the server API
 * for feature extraction and storage. The server extracts 13-dim DSP
 * features and stores the centroid vector.
 *
 * Phase 0: Server-side feature extraction (send WAV, server returns result)
 * Phase 1+: On-device DSP/ONNX extraction (send only the 13/192-dim vector)
 *
 * Features:
 * - Audio recording via expo-av (16kHz, mono, 16-bit PCM WAV)
 * - Base64 WAV encoding via expo-file-system
 * - API integration with Vouch Voice ID endpoints
 * - Local enrollment status tracking (AsyncStorage)
 * - Recording level metering for UI feedback
 *
 * @module VoiceIdService
 */

import { Audio, InterruptionModeIOS, InterruptionModeAndroid } from 'expo-av';
import * as FileSystem from 'expo-file-system';
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';

// =============================================================================
// Types
// =============================================================================

export interface VoiceIdStatus {
    enrolled: boolean;
    sampleCount: number;
    enrolledAt: string | null;
    did: string | null;
    voiceprintHash: string | null;
}

export interface EnrollResult {
    success: boolean;
    sampleCount: number;
    voiceprintHash?: string;
    enrolledAt?: string;
    error?: string;
}

export interface VerifyResult {
    match: boolean;
    confidence: number;
    did?: string;
    displayName?: string;
    error?: string;
}

export interface RecordingState {
    isRecording: boolean;
    durationMs: number;
    meterLevel: number; // -160 to 0 dB
}

export type RecordingCallback = (state: RecordingState) => void;

// =============================================================================
// Constants
// =============================================================================

const MIN_ENROLLMENT_SAMPLES = 3;
const MIN_RECORDING_DURATION_MS = 2000; // 2 seconds minimum
const MAX_RECORDING_DURATION_MS = 10000; // 10 seconds maximum
const DEFAULT_API_BASE = 'https://vouch-protocol.com';

const STORAGE_KEYS = {
    VOICE_STATUS: 'vouch_voice_id_status',
    API_BASE: 'vouch_api_base',
    LICENSE_KEY: 'vouch_license_key',
} as const;

// =============================================================================
// VoiceIdService Class
// =============================================================================

class VoiceIdService {
    private static instance: VoiceIdService;
    private recording: Audio.Recording | null = null;
    private apiBase: string = DEFAULT_API_BASE;
    private licenseKey: string | null = null;
    private initialized = false;
    private meterInterval: ReturnType<typeof setInterval> | null = null;
    private recordingStartTime = 0;

    private constructor() {}

    /**
     * Get singleton instance
     */
    static getInstance(): VoiceIdService {
        if (!VoiceIdService.instance) {
            VoiceIdService.instance = new VoiceIdService();
        }
        return VoiceIdService.instance;
    }

    /**
     * Initialize the service - load saved config
     */
    async initialize(): Promise<void> {
        if (this.initialized) return;

        const savedBase = await AsyncStorage.getItem(STORAGE_KEYS.API_BASE);
        if (savedBase) this.apiBase = savedBase;

        const savedKey = await SecureStore.getItemAsync(STORAGE_KEYS.LICENSE_KEY);
        if (savedKey) this.licenseKey = savedKey;

        this.initialized = true;
        console.log('[VoiceIdService] Initialized');
    }

    /**
     * Set the API base URL
     */
    async setApiBase(url: string): Promise<void> {
        this.apiBase = url;
        await AsyncStorage.setItem(STORAGE_KEYS.API_BASE, url);
    }

    /**
     * Set the license key (stored securely)
     */
    async setLicenseKey(key: string): Promise<void> {
        this.licenseKey = key;
        await SecureStore.setItemAsync(STORAGE_KEYS.LICENSE_KEY, key, {
            keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
        });
    }

    /**
     * Check if license key is configured
     */
    hasLicenseKey(): boolean {
        return this.licenseKey !== null;
    }

    // =========================================================================
    // Audio Recording
    // =========================================================================

    /**
     * Request microphone permissions
     */
    async requestPermissions(): Promise<boolean> {
        const { status } = await Audio.requestPermissionsAsync();
        return status === 'granted';
    }

    /**
     * Start recording audio (16kHz mono WAV)
     */
    async startRecording(onUpdate?: RecordingCallback): Promise<void> {
        if (this.recording) {
            await this.stopRecording();
        }

        await Audio.setAudioModeAsync({
            allowsRecordingIOS: true,
            playsInSilentModeIOS: true,
            interruptionModeIOS: InterruptionModeIOS.DoNotMix,
            interruptionModeAndroid: InterruptionModeAndroid.DoNotMix,
        });

        const { recording } = await Audio.Recording.createAsync({
            isMeteringEnabled: true,
            android: {
                extension: '.wav',
                outputFormat: Audio.AndroidOutputFormat.DEFAULT,
                audioEncoder: Audio.AndroidAudioEncoder.DEFAULT,
                sampleRate: 16000,
                numberOfChannels: 1,
                bitRate: 256000,
            },
            ios: {
                extension: '.wav',
                audioQuality: Audio.IOSAudioQuality.HIGH,
                sampleRate: 16000,
                numberOfChannels: 1,
                bitRate: 256000,
                linearPCMBitDepth: 16,
                linearPCMIsBigEndian: false,
                linearPCMIsFloat: false,
            },
            web: {},
        });

        this.recording = recording;
        this.recordingStartTime = Date.now();

        // Start metering updates
        if (onUpdate) {
            this.meterInterval = setInterval(async () => {
                if (!this.recording) return;
                try {
                    const status = await this.recording.getStatusAsync();
                    onUpdate({
                        isRecording: status.isRecording,
                        durationMs: status.durationMillis,
                        meterLevel: status.metering ?? -160,
                    });

                    // Auto-stop at max duration
                    if (status.durationMillis >= MAX_RECORDING_DURATION_MS) {
                        await this.stopRecording();
                        onUpdate({
                            isRecording: false,
                            durationMs: status.durationMillis,
                            meterLevel: -160,
                        });
                    }
                } catch {
                    // Recording may have been stopped
                }
            }, 100);
        }

        console.log('[VoiceIdService] Recording started');
    }

    /**
     * Stop recording and return the file URI
     */
    async stopRecording(): Promise<string | null> {
        if (this.meterInterval) {
            clearInterval(this.meterInterval);
            this.meterInterval = null;
        }

        if (!this.recording) return null;

        try {
            await this.recording.stopAndUnloadAsync();
        } catch {
            // May already be stopped
        }

        const uri = this.recording.getURI();
        this.recording = null;

        await Audio.setAudioModeAsync({
            allowsRecordingIOS: false,
        });

        console.log('[VoiceIdService] Recording stopped:', uri);
        return uri;
    }

    /**
     * Check if currently recording
     */
    get isRecording(): boolean {
        return this.recording !== null;
    }

    /**
     * Get recording duration so far
     */
    getRecordingDuration(): number {
        if (!this.recording) return 0;
        return Date.now() - this.recordingStartTime;
    }

    // =========================================================================
    // API: Enrollment
    // =========================================================================

    /**
     * Enroll a voice sample from a recorded WAV file.
     *
     * Reads the WAV file, base64-encodes it, and sends to the server API.
     * The server extracts 13-dim DSP features and stores the centroid.
     */
    async enrollFromFile(
        fileUri: string,
        did: string,
        displayName: string
    ): Promise<EnrollResult> {
        if (!this.licenseKey) {
            return { success: false, sampleCount: 0, error: 'License key not configured. Set it in Settings.' };
        }

        // Validate recording duration
        const fileInfo = await FileSystem.getInfoAsync(fileUri);
        if (!fileInfo.exists) {
            return { success: false, sampleCount: 0, error: 'Recording file not found' };
        }

        // Read file as base64
        const base64Audio = await FileSystem.readAsStringAsync(fileUri, {
            encoding: FileSystem.EncodingType.Base64,
        });

        // Check minimum size (2 seconds of 16kHz mono 16-bit = ~64KB)
        if (base64Audio.length < 10000) {
            return { success: false, sampleCount: 0, error: 'Recording too short. Please record at least 2 seconds.' };
        }

        try {
            const response = await fetch(`${this.apiBase}/api/v1/voice-id/enroll`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.licenseKey}`,
                },
                body: JSON.stringify({
                    audio: base64Audio,
                    did,
                    displayName,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                return {
                    success: false,
                    sampleCount: 0,
                    error: data.error || `Server error (${response.status})`,
                };
            }

            // Update local status
            const status: VoiceIdStatus = {
                enrolled: data.sampleCount >= MIN_ENROLLMENT_SAMPLES,
                sampleCount: data.sampleCount,
                enrolledAt: data.enrolledAt,
                did,
                voiceprintHash: data.voiceprintHash || null,
            };
            await this.saveLocalStatus(status);

            // Clean up recorded file
            await FileSystem.deleteAsync(fileUri, { idempotent: true });

            return {
                success: true,
                sampleCount: data.sampleCount,
                voiceprintHash: data.voiceprintHash,
                enrolledAt: data.enrolledAt,
            };
        } catch (error) {
            return {
                success: false,
                sampleCount: 0,
                error: error instanceof Error ? error.message : 'Network error. Check your connection.',
            };
        }
    }

    // =========================================================================
    // API: Verification
    // =========================================================================

    /**
     * Verify a voice sample from a recorded WAV file.
     *
     * Reads the WAV file, base64-encodes it, and sends to the server API.
     * The server compares the extracted features against the stored centroid.
     */
    async verifyFromFile(
        fileUri: string,
        did: string
    ): Promise<VerifyResult> {
        if (!this.licenseKey) {
            return { match: false, confidence: 0, error: 'License key not configured.' };
        }

        const base64Audio = await FileSystem.readAsStringAsync(fileUri, {
            encoding: FileSystem.EncodingType.Base64,
        });

        if (base64Audio.length < 10000) {
            return { match: false, confidence: 0, error: 'Recording too short.' };
        }

        try {
            const response = await fetch(`${this.apiBase}/api/v1/voice-id/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.licenseKey}`,
                },
                body: JSON.stringify({
                    audio: base64Audio,
                    did,
                }),
            });

            const data = await response.json();

            // Clean up
            await FileSystem.deleteAsync(fileUri, { idempotent: true });

            if (!response.ok) {
                return {
                    match: false,
                    confidence: 0,
                    error: data.error || `Server error (${response.status})`,
                };
            }

            return {
                match: data.match,
                confidence: data.confidence,
                did: data.did,
                displayName: data.displayName,
            };
        } catch (error) {
            return {
                match: false,
                confidence: 0,
                error: error instanceof Error ? error.message : 'Network error.',
            };
        }
    }

    // =========================================================================
    // Local Status
    // =========================================================================

    /**
     * Get locally cached enrollment status
     */
    async getLocalStatus(): Promise<VoiceIdStatus> {
        const data = await AsyncStorage.getItem(STORAGE_KEYS.VOICE_STATUS);
        if (!data) {
            return {
                enrolled: false,
                sampleCount: 0,
                enrolledAt: null,
                did: null,
                voiceprintHash: null,
            };
        }
        return JSON.parse(data);
    }

    /**
     * Save enrollment status locally
     */
    private async saveLocalStatus(status: VoiceIdStatus): Promise<void> {
        await AsyncStorage.setItem(STORAGE_KEYS.VOICE_STATUS, JSON.stringify(status));
    }

    /**
     * Clear local Voice ID status (for re-enrollment)
     */
    async clearLocalStatus(): Promise<void> {
        await AsyncStorage.removeItem(STORAGE_KEYS.VOICE_STATUS);
    }
}

// =============================================================================
// Exports
// =============================================================================

export const voiceIdService = VoiceIdService.getInstance();

export default voiceIdService;
