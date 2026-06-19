/**
 * Voice ID Screen - Voice Biometric Enrollment & Verification
 *
 * Professional+ feature. Allows users to:
 * - Enroll their voice with 3 samples
 * - Verify their identity via voice
 * - View enrollment status
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
    View,
    Text,
    TouchableOpacity,
    StyleSheet,
    SafeAreaView,
    StatusBar,
    ScrollView,
    Animated,
    Alert,
    ActivityIndicator,
} from 'react-native';
import { router } from 'expo-router';
import voiceIdService, {
    VoiceIdStatus,
    RecordingState,
} from '@/services/VoiceIdService';
import identityService from '@/services/IdentityService';

// =============================================================================
// Constants
// =============================================================================

const MIN_SAMPLES = 3;
const PROMPTS = [
    'Say: "My voice is my identity"',
    'Say: "I am the owner of this key"',
    'Say: "Verify my voice, confirm my proof"',
    'Say any sentence for at least 3 seconds',
    'Read aloud from any text nearby',
];

// =============================================================================
// Voice ID Screen
// =============================================================================

export default function VoiceIdScreen() {
    const [isLoading, setIsLoading] = useState(true);
    const [voiceStatus, setVoiceStatus] = useState<VoiceIdStatus | null>(null);
    const [did, setDid] = useState<string | null>(null);
    const [displayName, setDisplayName] = useState('');
    const [hasPermission, setHasPermission] = useState(false);

    // Recording state
    const [isRecording, setIsRecording] = useState(false);
    const [recordingDuration, setRecordingDuration] = useState(0);
    const [meterLevel, setMeterLevel] = useState(-160);

    // Enrollment state
    const [enrolling, setEnrolling] = useState(false);
    const [currentPromptIndex, setCurrentPromptIndex] = useState(0);
    const [enrollError, setEnrollError] = useState<string | null>(null);

    // Verification state
    const [verifying, setVerifying] = useState(false);
    const [verifyResult, setVerifyResult] = useState<{
        match: boolean;
        confidence: number;
    } | null>(null);

    // Animation
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const levelAnim = useRef(new Animated.Value(0)).current;

    // Initialize
    useEffect(() => {
        const init = async () => {
            try {
                await voiceIdService.initialize();
                const identity = await identityService.getDeviceIdentity();
                if (identity) {
                    setDid(identity.did);
                    setDisplayName('Mobile Device');
                }

                const permission = await voiceIdService.requestPermissions();
                setHasPermission(permission);

                const status = await voiceIdService.getLocalStatus();
                setVoiceStatus(status);
            } catch (error) {
                console.error('Voice ID init error:', error);
            } finally {
                setIsLoading(false);
            }
        };

        init();
    }, []);

    // Pulse animation for recording indicator
    useEffect(() => {
        if (isRecording) {
            const pulse = Animated.loop(
                Animated.sequence([
                    Animated.timing(pulseAnim, {
                        toValue: 1.3,
                        duration: 600,
                        useNativeDriver: true,
                    }),
                    Animated.timing(pulseAnim, {
                        toValue: 1,
                        duration: 600,
                        useNativeDriver: true,
                    }),
                ])
            );
            pulse.start();
            return () => pulse.stop();
        } else {
            pulseAnim.setValue(1);
        }
    }, [isRecording]);

    // Meter level animation
    useEffect(() => {
        Animated.spring(levelAnim, {
            toValue: Math.min(1, (meterLevel + 60) / 50),
            useNativeDriver: true,
            tension: 120,
            friction: 8,
        }).start();
    }, [meterLevel]);

    // Recording update callback
    const handleRecordingUpdate = useCallback((state: RecordingState) => {
        setIsRecording(state.isRecording);
        setRecordingDuration(state.durationMs);
        setMeterLevel(state.meterLevel);
    }, []);

    // Start recording
    const handleStartRecording = useCallback(async () => {
        if (!hasPermission) {
            const granted = await voiceIdService.requestPermissions();
            setHasPermission(granted);
            if (!granted) {
                Alert.alert(
                    'Microphone Required',
                    'Voice ID needs microphone access. Please enable it in Settings.'
                );
                return;
            }
        }

        setEnrollError(null);
        setVerifyResult(null);

        try {
            await voiceIdService.startRecording(handleRecordingUpdate);
            setIsRecording(true);
        } catch (error) {
            Alert.alert('Error', 'Failed to start recording. Please try again.');
            console.error('Recording start error:', error);
        }
    }, [hasPermission, handleRecordingUpdate]);

    // Stop recording and enroll
    const handleStopAndEnroll = useCallback(async () => {
        if (!did) return;

        setEnrolling(true);
        setEnrollError(null);

        try {
            const uri = await voiceIdService.stopRecording();
            setIsRecording(false);

            if (!uri) {
                setEnrollError('No recording captured. Try again.');
                setEnrolling(false);
                return;
            }

            const result = await voiceIdService.enrollFromFile(uri, did, displayName);

            if (result.success) {
                const newStatus: VoiceIdStatus = {
                    enrolled: result.sampleCount >= MIN_SAMPLES,
                    sampleCount: result.sampleCount,
                    enrolledAt: result.enrolledAt || null,
                    did,
                    voiceprintHash: result.voiceprintHash || null,
                };
                setVoiceStatus(newStatus);

                // Move to next prompt
                setCurrentPromptIndex((prev) => (prev + 1) % PROMPTS.length);

                if (result.sampleCount >= MIN_SAMPLES) {
                    Alert.alert(
                        'Enrollment Complete',
                        'Your Voice ID is now active. You can verify your identity using your voice.'
                    );
                }
            } else {
                setEnrollError(result.error || 'Enrollment failed');
            }
        } catch (error) {
            setEnrollError(error instanceof Error ? error.message : 'Unexpected error');
        } finally {
            setEnrolling(false);
        }
    }, [did, displayName]);

    // Stop recording and verify
    const handleStopAndVerify = useCallback(async () => {
        if (!did) return;

        setVerifying(true);
        setVerifyResult(null);

        try {
            const uri = await voiceIdService.stopRecording();
            setIsRecording(false);

            if (!uri) {
                setVerifyResult({ match: false, confidence: 0 });
                setVerifying(false);
                return;
            }

            const result = await voiceIdService.verifyFromFile(uri, did);

            if (result.error) {
                Alert.alert('Verification Error', result.error);
                setVerifyResult(null);
            } else {
                setVerifyResult({
                    match: result.match,
                    confidence: result.confidence,
                });
            }
        } catch (error) {
            Alert.alert('Error', 'Verification failed. Please try again.');
        } finally {
            setVerifying(false);
        }
    }, [did]);

    // Cancel recording
    const handleCancelRecording = useCallback(async () => {
        await voiceIdService.stopRecording();
        setIsRecording(false);
    }, []);

    // Re-enroll
    const handleReEnroll = useCallback(() => {
        Alert.alert(
            'Re-enroll Voice ID',
            'This will clear your current voice enrollment and start fresh. Continue?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Re-enroll',
                    style: 'destructive',
                    onPress: async () => {
                        await voiceIdService.clearLocalStatus();
                        setVoiceStatus({
                            enrolled: false,
                            sampleCount: 0,
                            enrolledAt: null,
                            did,
                            voiceprintHash: null,
                        });
                        setCurrentPromptIndex(0);
                        setVerifyResult(null);
                    },
                },
            ]
        );
    }, [did]);

    // Format duration
    const formatDuration = (ms: number) => {
        const seconds = Math.floor(ms / 1000);
        return `${seconds}s`;
    };

    // Loading state
    if (isLoading) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar barStyle="light-content" />
                <View style={styles.loadingContainer}>
                    <ActivityIndicator size="large" color="#8b5cf6" />
                    <Text style={styles.loadingText}>Loading Voice ID...</Text>
                </View>
            </SafeAreaView>
        );
    }

    // No identity
    if (!did) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar barStyle="light-content" />
                <View style={styles.header}>
                    <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                        <Text style={styles.backText}>Back</Text>
                    </TouchableOpacity>
                    <Text style={styles.title}>Voice ID</Text>
                </View>
                <View style={styles.centeredContent}>
                    <Text style={styles.noIdentityText}>
                        Create your Vouch identity first to use Voice ID.
                    </Text>
                    <TouchableOpacity
                        style={styles.primaryButton}
                        onPress={() => router.push('/identity')}
                    >
                        <Text style={styles.primaryButtonText}>Go to Identity</Text>
                    </TouchableOpacity>
                </View>
            </SafeAreaView>
        );
    }

    // No license key
    if (!voiceIdService.hasLicenseKey()) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar barStyle="light-content" />
                <View style={styles.header}>
                    <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                        <Text style={styles.backText}>Back</Text>
                    </TouchableOpacity>
                    <Text style={styles.title}>Voice ID</Text>
                </View>
                <View style={styles.centeredContent}>
                    <View style={styles.infoCard}>
                        <Text style={styles.infoTitle}>Professional Plan Required</Text>
                        <Text style={styles.infoText}>
                            Voice ID is available on Professional and higher plans.
                            Enter your license key in the app settings to get started.
                        </Text>
                    </View>
                </View>
            </SafeAreaView>
        );
    }

    const enrolled = voiceStatus?.enrolled ?? false;
    const sampleCount = voiceStatus?.sampleCount ?? 0;
    const samplesRemaining = Math.max(0, MIN_SAMPLES - sampleCount);

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar barStyle="light-content" />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <Text style={styles.backText}>Back</Text>
                </TouchableOpacity>
                <Text style={styles.title}>Voice ID</Text>
                {enrolled && (
                    <View style={styles.enrolledBadge}>
                        <Text style={styles.enrolledBadgeText}>Active</Text>
                    </View>
                )}
            </View>

            <ScrollView style={styles.content} contentContainerStyle={styles.contentContainer}>
                {/* Status Card */}
                <View style={[styles.statusCard, enrolled ? styles.statusCardActive : styles.statusCardPending]}>
                    <View style={styles.statusRow}>
                        <Text style={styles.statusLabel}>Status</Text>
                        <Text style={[styles.statusValue, enrolled ? styles.statusValueActive : styles.statusValuePending]}>
                            {enrolled ? 'Enrolled' : 'Not Enrolled'}
                        </Text>
                    </View>
                    <View style={styles.statusRow}>
                        <Text style={styles.statusLabel}>Samples</Text>
                        <Text style={styles.statusValue}>
                            {sampleCount} / {MIN_SAMPLES}{sampleCount >= MIN_SAMPLES ? '+' : ''}
                        </Text>
                    </View>
                    {voiceStatus?.enrolledAt && (
                        <View style={styles.statusRow}>
                            <Text style={styles.statusLabel}>Enrolled</Text>
                            <Text style={styles.statusValue}>
                                {new Date(voiceStatus.enrolledAt).toLocaleDateString()}
                            </Text>
                        </View>
                    )}

                    {/* Progress bar */}
                    {!enrolled && (
                        <View style={styles.progressContainer}>
                            <View style={styles.progressTrack}>
                                <View
                                    style={[
                                        styles.progressFill,
                                        { width: `${Math.min(100, (sampleCount / MIN_SAMPLES) * 100)}%` },
                                    ]}
                                />
                            </View>
                            <Text style={styles.progressText}>
                                {samplesRemaining} more sample{samplesRemaining !== 1 ? 's' : ''} needed
                            </Text>
                        </View>
                    )}
                </View>

                {/* Recording Section */}
                {!enrolled || isRecording ? (
                    <>
                        {/* Enrollment Mode */}
                        <View style={styles.section}>
                            <Text style={styles.sectionTitle}>
                                {enrolled ? 'Add Voice Sample' : 'Voice Enrollment'}
                            </Text>
                            <Text style={styles.prompt}>
                                {PROMPTS[currentPromptIndex % PROMPTS.length]}
                            </Text>
                        </View>

                        {/* Audio Visualizer */}
                        <View style={styles.visualizerContainer}>
                            <Animated.View
                                style={[
                                    styles.visualizerCircle,
                                    isRecording && styles.visualizerCircleActive,
                                    {
                                        transform: [{ scale: isRecording ? pulseAnim : 1 }],
                                    },
                                ]}
                            >
                                <Animated.View
                                    style={[
                                        styles.levelIndicator,
                                        {
                                            transform: [{ scaleY: levelAnim }],
                                        },
                                    ]}
                                />
                                {isRecording ? (
                                    <Text style={styles.visualizerText}>
                                        {formatDuration(recordingDuration)}
                                    </Text>
                                ) : (
                                    <Text style={styles.visualizerText}>Tap to record</Text>
                                )}
                            </Animated.View>
                        </View>

                        {/* Controls */}
                        <View style={styles.controlsContainer}>
                            {isRecording ? (
                                <View style={styles.recordingControls}>
                                    <TouchableOpacity
                                        style={styles.cancelButton}
                                        onPress={handleCancelRecording}
                                    >
                                        <Text style={styles.cancelButtonText}>Cancel</Text>
                                    </TouchableOpacity>
                                    <TouchableOpacity
                                        style={[
                                            styles.stopButton,
                                            recordingDuration < 2000 && styles.buttonDisabled,
                                        ]}
                                        onPress={handleStopAndEnroll}
                                        disabled={recordingDuration < 2000 || enrolling}
                                    >
                                        {enrolling ? (
                                            <ActivityIndicator color="#fff" size="small" />
                                        ) : (
                                            <Text style={styles.stopButtonText}>
                                                Stop & Enroll
                                            </Text>
                                        )}
                                    </TouchableOpacity>
                                </View>
                            ) : (
                                <TouchableOpacity
                                    style={styles.recordButton}
                                    onPress={handleStartRecording}
                                    disabled={enrolling}
                                >
                                    <View style={styles.recordDot} />
                                    <Text style={styles.recordButtonText}>
                                        Record Sample {sampleCount + 1}
                                    </Text>
                                </TouchableOpacity>
                            )}
                        </View>

                        {enrollError && (
                            <View style={styles.errorCard}>
                                <Text style={styles.errorText}>{enrollError}</Text>
                            </View>
                        )}

                        <Text style={styles.hintText}>
                            Record at least 2 seconds in a quiet environment.
                            Hold the phone 15-30 cm from your mouth.
                        </Text>
                    </>
                ) : (
                    <>
                        {/* Verification Mode (shown when enrolled) */}
                        <View style={styles.section}>
                            <Text style={styles.sectionTitle}>Voice Verification</Text>
                            <Text style={styles.sectionSubtitle}>
                                Speak to verify your identity
                            </Text>
                        </View>

                        {/* Verify Visualizer */}
                        <View style={styles.visualizerContainer}>
                            <Animated.View
                                style={[
                                    styles.visualizerCircle,
                                    styles.visualizerCircleVerify,
                                    isRecording && styles.visualizerCircleActive,
                                    {
                                        transform: [{ scale: isRecording ? pulseAnim : 1 }],
                                    },
                                ]}
                            >
                                {verifyResult ? (
                                    <>
                                        <Text style={[
                                            styles.verifyResultEmoji,
                                        ]}>
                                            {verifyResult.match ? 'Verified' : 'No Match'}
                                        </Text>
                                        <Text style={styles.verifyConfidence}>
                                            {verifyResult.confidence}%
                                        </Text>
                                    </>
                                ) : (
                                    <Text style={styles.visualizerText}>
                                        {isRecording ? formatDuration(recordingDuration) : 'Ready'}
                                    </Text>
                                )}
                            </Animated.View>
                        </View>

                        {/* Verify Result Card */}
                        {verifyResult && (
                            <View style={[
                                styles.resultCard,
                                verifyResult.match ? styles.resultCardMatch : styles.resultCardNoMatch,
                            ]}>
                                <Text style={styles.resultTitle}>
                                    {verifyResult.match ? 'Voice Matched' : 'Voice Did Not Match'}
                                </Text>
                                <Text style={styles.resultConfidence}>
                                    Confidence: {verifyResult.confidence}%
                                </Text>
                                <Text style={styles.resultHint}>
                                    {verifyResult.match
                                        ? 'Your voice matches the enrolled voiceprint.'
                                        : 'Try again in a quieter environment, or re-enroll if needed.'}
                                </Text>
                            </View>
                        )}

                        {/* Verify Controls */}
                        <View style={styles.controlsContainer}>
                            {isRecording ? (
                                <View style={styles.recordingControls}>
                                    <TouchableOpacity
                                        style={styles.cancelButton}
                                        onPress={handleCancelRecording}
                                    >
                                        <Text style={styles.cancelButtonText}>Cancel</Text>
                                    </TouchableOpacity>
                                    <TouchableOpacity
                                        style={[
                                            styles.verifyStopButton,
                                            recordingDuration < 2000 && styles.buttonDisabled,
                                        ]}
                                        onPress={handleStopAndVerify}
                                        disabled={recordingDuration < 2000 || verifying}
                                    >
                                        {verifying ? (
                                            <ActivityIndicator color="#fff" size="small" />
                                        ) : (
                                            <Text style={styles.stopButtonText}>
                                                Stop & Verify
                                            </Text>
                                        )}
                                    </TouchableOpacity>
                                </View>
                            ) : (
                                <TouchableOpacity
                                    style={styles.verifyButton}
                                    onPress={handleStartRecording}
                                    disabled={verifying}
                                >
                                    <Text style={styles.verifyButtonText}>
                                        Verify My Voice
                                    </Text>
                                </TouchableOpacity>
                            )}
                        </View>

                        {/* Actions */}
                        <View style={styles.actionsSection}>
                            <TouchableOpacity
                                style={styles.secondaryButton}
                                onPress={handleStartRecording}
                                disabled={isRecording}
                            >
                                <Text style={styles.secondaryButtonText}>
                                    Add More Samples ({sampleCount} enrolled)
                                </Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={styles.dangerButton}
                                onPress={handleReEnroll}
                            >
                                <Text style={styles.dangerButtonText}>Re-enroll Voice ID</Text>
                            </TouchableOpacity>
                        </View>
                    </>
                )}
            </ScrollView>
        </SafeAreaView>
    );
}

// =============================================================================
// Styles
// =============================================================================

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#0a0a0f',
    },
    loadingContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    loadingText: {
        color: '#a0a0b0',
        marginTop: 16,
        fontSize: 16,
    },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 20,
        paddingVertical: 16,
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(255, 255, 255, 0.1)',
    },
    backButton: {
        marginRight: 16,
    },
    backText: {
        color: '#8b5cf6',
        fontSize: 16,
    },
    title: {
        fontSize: 20,
        fontWeight: '700',
        color: '#ffffff',
        flex: 1,
    },
    enrolledBadge: {
        backgroundColor: 'rgba(16, 185, 129, 0.2)',
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: 'rgba(16, 185, 129, 0.3)',
    },
    enrolledBadgeText: {
        color: '#10b981',
        fontSize: 12,
        fontWeight: '600',
    },
    content: {
        flex: 1,
    },
    contentContainer: {
        padding: 20,
        paddingBottom: 40,
    },
    centeredContent: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 20,
    },
    noIdentityText: {
        color: '#a0a0b0',
        fontSize: 16,
        textAlign: 'center',
        marginBottom: 24,
    },

    // Status Card
    statusCard: {
        borderRadius: 16,
        padding: 16,
        marginBottom: 24,
        borderWidth: 1,
    },
    statusCardActive: {
        backgroundColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.2)',
    },
    statusCardPending: {
        backgroundColor: 'rgba(251, 191, 36, 0.1)',
        borderColor: 'rgba(251, 191, 36, 0.2)',
    },
    statusRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 6,
    },
    statusLabel: {
        color: '#a0a0b0',
        fontSize: 14,
    },
    statusValue: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '600',
    },
    statusValueActive: {
        color: '#10b981',
    },
    statusValuePending: {
        color: '#fbbf24',
    },
    progressContainer: {
        marginTop: 12,
    },
    progressTrack: {
        height: 4,
        backgroundColor: 'rgba(255, 255, 255, 0.1)',
        borderRadius: 2,
        overflow: 'hidden',
    },
    progressFill: {
        height: '100%',
        backgroundColor: '#8b5cf6',
        borderRadius: 2,
    },
    progressText: {
        color: '#a0a0b0',
        fontSize: 12,
        marginTop: 6,
        textAlign: 'center',
    },

    // Section
    section: {
        marginBottom: 16,
    },
    sectionTitle: {
        color: '#ffffff',
        fontSize: 18,
        fontWeight: '700',
        marginBottom: 4,
    },
    sectionSubtitle: {
        color: '#a0a0b0',
        fontSize: 14,
    },
    prompt: {
        color: '#8b5cf6',
        fontSize: 16,
        fontWeight: '500',
        fontStyle: 'italic',
        marginTop: 4,
    },

    // Visualizer
    visualizerContainer: {
        alignItems: 'center',
        paddingVertical: 24,
    },
    visualizerCircle: {
        width: 140,
        height: 140,
        borderRadius: 70,
        backgroundColor: 'rgba(139, 92, 246, 0.15)',
        borderWidth: 3,
        borderColor: '#8b5cf6',
        justifyContent: 'center',
        alignItems: 'center',
        overflow: 'hidden',
    },
    visualizerCircleVerify: {
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.15)',
    },
    visualizerCircleActive: {
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
    },
    levelIndicator: {
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        height: '100%',
        backgroundColor: 'rgba(139, 92, 246, 0.3)',
        transformOrigin: 'bottom',
    },
    visualizerText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
        zIndex: 1,
    },
    verifyResultEmoji: {
        fontSize: 16,
        fontWeight: '700',
        color: '#ffffff',
        zIndex: 1,
    },
    verifyConfidence: {
        fontSize: 24,
        fontWeight: '700',
        color: '#ffffff',
        zIndex: 1,
        marginTop: 4,
    },

    // Controls
    controlsContainer: {
        marginBottom: 16,
    },
    recordingControls: {
        flexDirection: 'row',
        gap: 12,
    },
    recordButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#8b5cf6',
        paddingVertical: 16,
        borderRadius: 16,
        gap: 10,
    },
    recordDot: {
        width: 12,
        height: 12,
        borderRadius: 6,
        backgroundColor: '#ef4444',
    },
    recordButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    cancelButton: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 16,
        borderRadius: 16,
        backgroundColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.2)',
    },
    cancelButtonText: {
        color: '#a0a0b0',
        fontSize: 16,
        fontWeight: '600',
    },
    stopButton: {
        flex: 2,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 16,
        borderRadius: 16,
        backgroundColor: '#8b5cf6',
    },
    verifyStopButton: {
        flex: 2,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 16,
        borderRadius: 16,
        backgroundColor: '#3b82f6',
    },
    stopButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    buttonDisabled: {
        opacity: 0.4,
    },
    verifyButton: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#3b82f6',
        paddingVertical: 16,
        borderRadius: 16,
    },
    verifyButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },

    // Error
    errorCard: {
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        borderRadius: 12,
        padding: 12,
        marginBottom: 16,
        borderWidth: 1,
        borderColor: 'rgba(239, 68, 68, 0.3)',
    },
    errorText: {
        color: '#fca5a5',
        fontSize: 14,
    },

    // Result
    resultCard: {
        borderRadius: 16,
        padding: 16,
        marginBottom: 16,
        borderWidth: 1,
    },
    resultCardMatch: {
        backgroundColor: 'rgba(16, 185, 129, 0.15)',
        borderColor: 'rgba(16, 185, 129, 0.3)',
    },
    resultCardNoMatch: {
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        borderColor: 'rgba(239, 68, 68, 0.3)',
    },
    resultTitle: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '700',
        marginBottom: 4,
    },
    resultConfidence: {
        color: '#a0a0b0',
        fontSize: 14,
        marginBottom: 8,
    },
    resultHint: {
        color: '#a0a0b0',
        fontSize: 13,
        lineHeight: 18,
    },

    // Hints
    hintText: {
        color: '#666',
        fontSize: 13,
        textAlign: 'center',
        lineHeight: 18,
        marginTop: 8,
    },

    // Actions
    actionsSection: {
        marginTop: 24,
        gap: 12,
    },
    primaryButton: {
        backgroundColor: '#8b5cf6',
        paddingVertical: 14,
        paddingHorizontal: 24,
        borderRadius: 12,
        alignItems: 'center',
    },
    primaryButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    secondaryButton: {
        alignItems: 'center',
        paddingVertical: 14,
        borderRadius: 12,
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    secondaryButtonText: {
        color: '#a0a0b0',
        fontSize: 14,
        fontWeight: '500',
    },
    dangerButton: {
        alignItems: 'center',
        paddingVertical: 14,
        borderRadius: 12,
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 1,
        borderColor: 'rgba(239, 68, 68, 0.2)',
    },
    dangerButtonText: {
        color: '#ef4444',
        fontSize: 14,
        fontWeight: '500',
    },

    // Info card
    infoCard: {
        backgroundColor: 'rgba(139, 92, 246, 0.15)',
        borderRadius: 16,
        padding: 20,
        borderWidth: 1,
        borderColor: 'rgba(139, 92, 246, 0.3)',
        maxWidth: 320,
    },
    infoTitle: {
        color: '#ffffff',
        fontSize: 18,
        fontWeight: '600',
        marginBottom: 8,
    },
    infoText: {
        color: '#a0a0b0',
        fontSize: 14,
        lineHeight: 20,
    },
});
