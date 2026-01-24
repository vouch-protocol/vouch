/**
 * Vouch Verifier - Home Screen
 *
 * Main screen with two action buttons:
 * - Verify Audio (Sonic Listener)
 * - Pair with Desktop (Bridge)
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
    View,
    Text,
    TouchableOpacity,
    StyleSheet,
    SafeAreaView,
    StatusBar,
    ActivityIndicator,
    Alert,
} from 'react-native';
import { router } from 'expo-router';
import identityService, {
    DeviceIdentity,
    BiometricCapability,
} from '@/services/IdentityService';

// =============================================================================
// Types
// =============================================================================

interface ActionButtonProps {
    emoji: string;
    title: string;
    subtitle: string;
    onPress: () => void;
    disabled?: boolean;
    gradient?: 'blue' | 'purple' | 'green';
}

// =============================================================================
// Components
// =============================================================================

const ActionButton: React.FC<ActionButtonProps> = ({
    emoji,
    title,
    subtitle,
    onPress,
    disabled,
    gradient = 'blue',
}) => {
    const gradientColors = {
        blue: ['#3b82f6', '#1d4ed8'],
        purple: ['#8b5cf6', '#6d28d9'],
        green: ['#10b981', '#047857'],
    };

    return (
        <TouchableOpacity
            style={[
                styles.actionButton,
                { backgroundColor: gradientColors[gradient][0] },
                disabled && styles.actionButtonDisabled,
            ]}
            onPress={onPress}
            disabled={disabled}
            activeOpacity={0.8}
        >
            <Text style={styles.actionEmoji}>{emoji}</Text>
            <Text style={styles.actionTitle}>{title}</Text>
            <Text style={styles.actionSubtitle}>{subtitle}</Text>
        </TouchableOpacity>
    );
};

// =============================================================================
// Home Screen
// =============================================================================

export default function HomeScreen() {
    const [isLoading, setIsLoading] = useState(true);
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [biometrics, setBiometrics] = useState<BiometricCapability | null>(null);

    // Initialize identity service
    useEffect(() => {
        const init = async () => {
            try {
                await identityService.initialize();
                const bio = await identityService.checkBiometricCapability();
                setBiometrics(bio);

                const hasId = await identityService.hasIdentity();
                if (hasId) {
                    const id = await identityService.getDeviceIdentity();
                    setIdentity(id);
                }
            } catch (error) {
                console.error('Init error:', error);
            } finally {
                setIsLoading(false);
            }
        };

        init();
    }, []);

    // Create identity if not exists
    const handleCreateIdentity = useCallback(async () => {
        try {
            setIsLoading(true);
            const keyPair = await identityService.generateHardwareKey({
                name: 'Device Root Key',
                type: 'root',
            });
            const id = await identityService.getDeviceIdentity();
            setIdentity(id);
            Alert.alert('Success', 'Your Vouch identity has been created!');
        } catch (error) {
            Alert.alert('Error', error instanceof Error ? error.message : 'Failed to create identity');
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Navigate to audio verification
    const handleVerifyAudio = useCallback(() => {
        router.push('/verify');
    }, []);

    // Navigate to desktop pairing
    const handlePairDesktop = useCallback(() => {
        router.push('/pair');
    }, []);

    // Navigate to identity settings
    const handleOpenIdentity = useCallback(() => {
        router.push('/identity');
    }, []);

    // Truncate DID for display
    const truncateDid = (did: string) => {
        if (did.length <= 24) return did;
        return `${did.slice(0, 12)}...${did.slice(-8)}`;
    };

    if (isLoading) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar barStyle="light-content" />
                <View style={styles.loadingContainer}>
                    <ActivityIndicator size="large" color="#6366f1" />
                    <Text style={styles.loadingText}>Initializing...</Text>
                </View>
            </SafeAreaView>
        );
    }

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar barStyle="light-content" />

            {/* Header */}
            <View style={styles.header}>
                <View style={styles.headerContent}>
                    <Text style={styles.appName}>Vouch Verifier</Text>
                    <TouchableOpacity onPress={handleOpenIdentity} style={styles.identityButton}>
                        {identity ? (
                            <>
                                <View style={styles.identityIndicator} />
                                <Text style={styles.identityText}>{truncateDid(identity.did)}</Text>
                            </>
                        ) : (
                            <Text style={styles.identityTextMuted}>No Identity</Text>
                        )}
                    </TouchableOpacity>
                </View>
            </View>

            {/* Main Content */}
            <View style={styles.content}>
                {/* Identity Setup (if needed) */}
                {!identity && (
                    <View style={styles.setupCard}>
                        <Text style={styles.setupTitle}>🔐 Setup Required</Text>
                        <Text style={styles.setupText}>
                            Create your Vouch identity to start verifying audio and signing content.
                        </Text>
                        <TouchableOpacity style={styles.setupButton} onPress={handleCreateIdentity}>
                            <Text style={styles.setupButtonText}>
                                {biometrics?.biometryType === 'FaceID' ? '👤 Create with Face ID' : '👆 Create with Fingerprint'}
                            </Text>
                        </TouchableOpacity>
                    </View>
                )}

                {/* Action Buttons */}
                <View style={styles.actionsContainer}>
                    <ActionButton
                        emoji="🎙️"
                        title="Verify Audio"
                        subtitle="Detect watermarks in real-time"
                        onPress={handleVerifyAudio}
                        gradient="blue"
                    />

                    <ActionButton
                        emoji="🔗"
                        title="Pair with Desktop"
                        subtitle="Scan QR to connect"
                        onPress={handlePairDesktop}
                        gradient="purple"
                        disabled={!identity}
                    />
                </View>

                {/* Status Cards */}
                <View style={styles.statusContainer}>
                    <View style={styles.statusCard}>
                        <Text style={styles.statusLabel}>Biometrics</Text>
                        <Text style={styles.statusValue}>
                            {biometrics?.available ? `${biometrics.biometryType} ✓` : 'Not Available'}
                        </Text>
                    </View>

                    <View style={styles.statusCard}>
                        <Text style={styles.statusLabel}>Sonic Engine</Text>
                        <Text style={styles.statusValue}>Ready</Text>
                    </View>
                </View>
            </View>

            {/* Footer */}
            <View style={styles.footer}>
                <Text style={styles.footerText}>Vouch Protocol v1.0.0</Text>
            </View>
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
        paddingHorizontal: 20,
        paddingTop: 16,
        paddingBottom: 12,
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(255, 255, 255, 0.1)',
    },
    headerContent: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
    },
    appName: {
        fontSize: 24,
        fontWeight: '700',
        color: '#ffffff',
    },
    identityButton: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: 'rgba(255, 255, 255, 0.1)',
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderRadius: 20,
    },
    identityIndicator: {
        width: 8,
        height: 8,
        borderRadius: 4,
        backgroundColor: '#10b981',
        marginRight: 8,
    },
    identityText: {
        color: '#ffffff',
        fontSize: 12,
        fontFamily: 'monospace',
    },
    identityTextMuted: {
        color: '#a0a0b0',
        fontSize: 12,
    },
    content: {
        flex: 1,
        padding: 20,
    },
    setupCard: {
        backgroundColor: 'rgba(99, 102, 241, 0.15)',
        borderRadius: 16,
        padding: 20,
        marginBottom: 24,
        borderWidth: 1,
        borderColor: 'rgba(99, 102, 241, 0.3)',
    },
    setupTitle: {
        fontSize: 18,
        fontWeight: '600',
        color: '#ffffff',
        marginBottom: 8,
    },
    setupText: {
        color: '#a0a0b0',
        fontSize: 14,
        lineHeight: 20,
        marginBottom: 16,
    },
    setupButton: {
        backgroundColor: '#6366f1',
        paddingVertical: 14,
        borderRadius: 12,
        alignItems: 'center',
    },
    setupButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    actionsContainer: {
        gap: 16,
        marginBottom: 24,
    },
    actionButton: {
        borderRadius: 20,
        padding: 24,
        alignItems: 'center',
    },
    actionButtonDisabled: {
        opacity: 0.5,
    },
    actionEmoji: {
        fontSize: 48,
        marginBottom: 12,
    },
    actionTitle: {
        fontSize: 20,
        fontWeight: '700',
        color: '#ffffff',
        marginBottom: 4,
    },
    actionSubtitle: {
        fontSize: 14,
        color: 'rgba(255, 255, 255, 0.7)',
    },
    statusContainer: {
        flexDirection: 'row',
        gap: 12,
    },
    statusCard: {
        flex: 1,
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 12,
        padding: 16,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    statusLabel: {
        color: '#a0a0b0',
        fontSize: 12,
        marginBottom: 4,
    },
    statusValue: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '600',
    },
    footer: {
        paddingVertical: 16,
        alignItems: 'center',
        borderTopWidth: 1,
        borderTopColor: 'rgba(255, 255, 255, 0.1)',
    },
    footerText: {
        color: '#666',
        fontSize: 12,
    },
});
