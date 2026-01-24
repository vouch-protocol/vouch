/**
 * Verify Screen - Audio Watermark Detection
 *
 * Uses the Vouch Sonic Engine to detect watermarks in real-time audio.
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
} from 'react-native';
import { router } from 'expo-router';
import SonicListener, {
    WatermarkResult,
    parseCovenant,
    formatConfidence,
    truncateDid,
} from '@/native/VouchSonicBridge';

// =============================================================================
// Types
// =============================================================================

interface VerificationResult {
    id: string;
    result: WatermarkResult;
    timestamp: Date;
}

// =============================================================================
// Verify Screen
// =============================================================================

export default function VerifyScreen() {
    const [isListening, setIsListening] = useState(false);
    const [audioLevel, setAudioLevel] = useState(-60);
    const [verifications, setVerifications] = useState<VerificationResult[]>([]);
    const [currentResult, setCurrentResult] = useState<WatermarkResult | null>(null);

    const listenerRef = useRef<SonicListener | null>(null);
    const levelAnimation = useRef(new Animated.Value(0)).current;

    // Initialize listener
    useEffect(() => {
        listenerRef.current = new SonicListener({
            sampleRate: 16000,
            detectionThreshold: 0.5,
        });

        return () => {
            listenerRef.current?.dispose();
        };
    }, []);

    // Animate audio level indicator
    useEffect(() => {
        Animated.spring(levelAnimation, {
            toValue: Math.min(1, (audioLevel + 60) / 60),
            useNativeDriver: true,
            tension: 100,
            friction: 10,
        }).start();
    }, [audioLevel]);

    // Start listening
    const handleStartListening = useCallback(async () => {
        if (!listenerRef.current) return;

        try {
            await listenerRef.current.start({
                onWatermarkDetected: (result) => {
                    setCurrentResult(result);
                    setVerifications((prev) => [
                        {
                            id: `${Date.now()}`,
                            result,
                            timestamp: new Date(),
                        },
                        ...prev.slice(0, 9), // Keep last 10
                    ]);
                },
                onAudioLevelChanged: (level) => {
                    setAudioLevel(level);
                },
                onError: (message) => {
                    console.error('Sonic error:', message);
                },
                onStateChanged: (state) => {
                    setIsListening(state === 'Listening');
                },
            });

            setIsListening(true);
        } catch (error) {
            console.error('Failed to start:', error);
        }
    }, []);

    // Stop listening
    const handleStopListening = useCallback(async () => {
        if (!listenerRef.current) return;

        try {
            await listenerRef.current.stop();
            setIsListening(false);
        } catch (error) {
            console.error('Failed to stop:', error);
        }
    }, []);

    // Format timestamp
    const formatTime = (date: Date) => {
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    };

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar barStyle="light-content" />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <Text style={styles.backText}>← Back</Text>
                </TouchableOpacity>
                <Text style={styles.title}>🎙️ Verify Audio</Text>
            </View>

            {/* Audio Visualizer */}
            <View style={styles.visualizerContainer}>
                <View style={styles.visualizer}>
                    <Animated.View
                        style={[
                            styles.levelBar,
                            {
                                transform: [
                                    {
                                        scaleY: levelAnimation,
                                    },
                                ],
                            },
                        ]}
                    />
                    <Text style={styles.levelText}>{audioLevel.toFixed(0)} dB</Text>
                </View>

                {/* Status */}
                <View style={styles.statusContainer}>
                    {isListening ? (
                        <>
                            <View style={styles.listeningIndicator} />
                            <Text style={styles.statusText}>Listening for watermarks...</Text>
                        </>
                    ) : (
                        <Text style={styles.statusTextMuted}>Tap Start to begin</Text>
                    )}
                </View>
            </View>

            {/* Control Button */}
            <View style={styles.controlContainer}>
                <TouchableOpacity
                    style={[
                        styles.controlButton,
                        isListening ? styles.controlButtonStop : styles.controlButtonStart,
                    ]}
                    onPress={isListening ? handleStopListening : handleStartListening}
                >
                    <Text style={styles.controlButtonEmoji}>
                        {isListening ? '⏹️' : '▶️'}
                    </Text>
                    <Text style={styles.controlButtonText}>
                        {isListening ? 'Stop Listening' : 'Start Listening'}
                    </Text>
                </TouchableOpacity>
            </View>

            {/* Current Detection (Modal-like) */}
            {currentResult?.detected && (
                <View style={styles.detectionCard}>
                    <Text style={styles.detectionTitle}>✅ Watermark Detected!</Text>
                    <View style={styles.detectionRow}>
                        <Text style={styles.detectionLabel}>Signer:</Text>
                        <Text style={styles.detectionValue}>
                            {currentResult.signerDid ? truncateDid(currentResult.signerDid) : 'Unknown'}
                        </Text>
                    </View>
                    <View style={styles.detectionRow}>
                        <Text style={styles.detectionLabel}>Confidence:</Text>
                        <Text style={styles.detectionValue}>
                            {formatConfidence(currentResult.confidence)}
                        </Text>
                    </View>
                    {currentResult.covenantJson && (
                        <View style={styles.covenantBadge}>
                            <Text style={styles.covenantText}>
                                📜 {parseCovenant(currentResult)?.aiTraining ? 'AI OK' : 'No AI Training'}
                            </Text>
                        </View>
                    )}
                </View>
            )}

            {/* History */}
            <View style={styles.historyHeader}>
                <Text style={styles.historyTitle}>Recent Verifications</Text>
                <Text style={styles.historyCount}>{verifications.length}</Text>
            </View>

            <ScrollView style={styles.historyList}>
                {verifications.length === 0 ? (
                    <Text style={styles.emptyText}>No verifications yet</Text>
                ) : (
                    verifications.map((item) => (
                        <View
                            key={item.id}
                            style={[
                                styles.historyItem,
                                item.result.detected ? styles.historyItemDetected : styles.historyItemNone,
                            ]}
                        >
                            <Text style={styles.historyEmoji}>
                                {item.result.detected ? '✅' : '❓'}
                            </Text>
                            <View style={styles.historyContent}>
                                <Text style={styles.historyStatus}>
                                    {item.result.detected ? 'Watermark Found' : 'No Watermark'}
                                </Text>
                                <Text style={styles.historyMeta}>
                                    {formatConfidence(item.result.confidence)} • {formatTime(item.timestamp)}
                                </Text>
                            </View>
                        </View>
                    ))
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
        color: '#6366f1',
        fontSize: 16,
    },
    title: {
        fontSize: 20,
        fontWeight: '700',
        color: '#ffffff',
    },
    visualizerContainer: {
        alignItems: 'center',
        paddingVertical: 32,
    },
    visualizer: {
        width: 120,
        height: 120,
        borderRadius: 60,
        backgroundColor: 'rgba(99, 102, 241, 0.2)',
        borderWidth: 3,
        borderColor: '#6366f1',
        justifyContent: 'center',
        alignItems: 'center',
        overflow: 'hidden',
    },
    levelBar: {
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        height: '100%',
        backgroundColor: 'rgba(99, 102, 241, 0.5)',
        transformOrigin: 'bottom',
    },
    levelText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
        zIndex: 1,
    },
    statusContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        marginTop: 16,
    },
    listeningIndicator: {
        width: 8,
        height: 8,
        borderRadius: 4,
        backgroundColor: '#ef4444',
        marginRight: 8,
    },
    statusText: {
        color: '#ffffff',
        fontSize: 14,
    },
    statusTextMuted: {
        color: '#666',
        fontSize: 14,
    },
    controlContainer: {
        paddingHorizontal: 20,
        marginBottom: 24,
    },
    controlButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 16,
        borderRadius: 16,
        gap: 12,
    },
    controlButtonStart: {
        backgroundColor: '#3b82f6',
    },
    controlButtonStop: {
        backgroundColor: '#ef4444',
    },
    controlButtonEmoji: {
        fontSize: 24,
    },
    controlButtonText: {
        color: '#ffffff',
        fontSize: 18,
        fontWeight: '600',
    },
    detectionCard: {
        marginHorizontal: 20,
        marginBottom: 24,
        backgroundColor: 'rgba(16, 185, 129, 0.15)',
        borderRadius: 16,
        padding: 16,
        borderWidth: 1,
        borderColor: 'rgba(16, 185, 129, 0.3)',
    },
    detectionTitle: {
        fontSize: 18,
        fontWeight: '700',
        color: '#10b981',
        marginBottom: 12,
    },
    detectionRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 8,
    },
    detectionLabel: {
        color: '#a0a0b0',
        fontSize: 14,
    },
    detectionValue: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '500',
        fontFamily: 'monospace',
    },
    covenantBadge: {
        backgroundColor: 'rgba(251, 191, 36, 0.2)',
        borderRadius: 8,
        paddingHorizontal: 12,
        paddingVertical: 6,
        alignSelf: 'flex-start',
        marginTop: 8,
    },
    covenantText: {
        color: '#fbbf24',
        fontSize: 12,
        fontWeight: '600',
    },
    historyHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingHorizontal: 20,
        marginBottom: 12,
    },
    historyTitle: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    historyCount: {
        color: '#666',
        fontSize: 14,
    },
    historyList: {
        flex: 1,
        paddingHorizontal: 20,
    },
    emptyText: {
        color: '#666',
        textAlign: 'center',
        marginTop: 32,
    },
    historyItem: {
        flexDirection: 'row',
        alignItems: 'center',
        padding: 12,
        borderRadius: 12,
        marginBottom: 8,
        borderWidth: 1,
    },
    historyItemDetected: {
        backgroundColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.2)',
    },
    historyItemNone: {
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    historyEmoji: {
        fontSize: 24,
        marginRight: 12,
    },
    historyContent: {
        flex: 1,
    },
    historyStatus: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '500',
    },
    historyMeta: {
        color: '#666',
        fontSize: 12,
        marginTop: 2,
    },
});
