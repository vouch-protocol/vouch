/**
 * Identity Screen - Device Identity Management
 *
 * View and manage device identity, keys, and biometric settings.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
    View,
    Text,
    TouchableOpacity,
    StyleSheet,
    SafeAreaView,
    StatusBar,
    ScrollView,
    Alert,
    Clipboard,
} from 'react-native';
import { router } from 'expo-router';
import identityService, {
    DeviceIdentity,
    BiometricCapability,
    StoredKeyPair,
} from '@/services/IdentityService';

// =============================================================================
// Identity Screen
// =============================================================================

export default function IdentityScreen() {
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [biometrics, setBiometrics] = useState<BiometricCapability | null>(null);
    const [keys, setKeys] = useState<StoredKeyPair[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    // Load data
    useEffect(() => {
        const load = async () => {
            try {
                const bio = await identityService.checkBiometricCapability();
                setBiometrics(bio);

                const id = await identityService.getDeviceIdentity();
                setIdentity(id);

                const keyIds = await identityService.getAllKeyIds();
                const keyPairs = await Promise.all(
                    keyIds.map((keyId) => identityService.getKeyPair(keyId))
                );
                setKeys(keyPairs.filter((k): k is StoredKeyPair => k !== null));
            } catch (error) {
                console.error('Load error:', error);
            } finally {
                setIsLoading(false);
            }
        };

        load();
    }, []);

    // Copy DID to clipboard
    const handleCopyDid = useCallback(() => {
        if (identity?.did) {
            // Note: Using deprecated Clipboard for demo, should use @react-native-clipboard/clipboard
            Clipboard.setString(identity.did);
            Alert.alert('Copied', 'DID copied to clipboard');
        }
    }, [identity]);

    // Create new identity
    const handleCreateIdentity = useCallback(async () => {
        try {
            setIsLoading(true);
            const keyPair = await identityService.generateHardwareKey({
                name: 'Device Root Key',
                type: 'root',
            });
            const id = await identityService.getDeviceIdentity();
            setIdentity(id);
            setKeys((prev) => [...prev, keyPair]);
            Alert.alert('Success', 'Identity created!');
        } catch (error) {
            Alert.alert('Error', error instanceof Error ? error.message : 'Failed');
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Create agent key
    const handleCreateAgent = useCallback(async () => {
        Alert.prompt(
            'Create Agent',
            'Enter a name for this agent identity:',
            async (name) => {
                if (!name) return;
                try {
                    const keyPair = await identityService.generateHardwareKey({
                        name,
                        type: 'agent',
                        parentKeyId: identity?.keyId,
                    });
                    setKeys((prev) => [...prev, keyPair]);
                    Alert.alert('Success', `Agent "${name}" created!`);
                } catch (error) {
                    Alert.alert('Error', error instanceof Error ? error.message : 'Failed');
                }
            },
            'plain-text',
            '',
            'default'
        );
    }, [identity]);

    // Delete key
    const handleDeleteKey = useCallback(async (keyId: string, name?: string) => {
        Alert.alert(
            'Delete Key',
            `Are you sure you want to delete "${name || keyId}"? This cannot be undone.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Delete',
                    style: 'destructive',
                    onPress: async () => {
                        const success = await identityService.deleteKey(keyId);
                        if (success) {
                            setKeys((prev) => prev.filter((k) => k.keyId !== keyId));
                            if (identity?.keyId === keyId) {
                                setIdentity(null);
                            }
                        }
                    },
                },
            ]
        );
    }, [identity]);

    // Format date
    const formatDate = (timestamp: number) => {
        return new Date(timestamp).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
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
                <Text style={styles.title}>👤 Identity</Text>
            </View>

            <ScrollView style={styles.content}>
                {/* Device Identity */}
                {identity ? (
                    <View style={styles.identityCard}>
                        <View style={styles.identityHeader}>
                            <View style={styles.identityIndicator} />
                            <Text style={styles.identityTitle}>Device Identity</Text>
                        </View>

                        <TouchableOpacity onPress={handleCopyDid} style={styles.didContainer}>
                            <Text style={styles.didLabel}>DID</Text>
                            <Text style={styles.didValue}>{identity.did}</Text>
                            <Text style={styles.didHint}>Tap to copy</Text>
                        </TouchableOpacity>

                        <View style={styles.identityMeta}>
                            <View style={styles.metaItem}>
                                <Text style={styles.metaLabel}>Created</Text>
                                <Text style={styles.metaValue}>{formatDate(identity.createdAt)}</Text>
                            </View>
                            <View style={styles.metaItem}>
                                <Text style={styles.metaLabel}>Biometrics</Text>
                                <Text style={styles.metaValue}>{identity.biometryType}</Text>
                            </View>
                        </View>
                    </View>
                ) : (
                    <View style={styles.noIdentityCard}>
                        <Text style={styles.noIdentityTitle}>No Identity Yet</Text>
                        <Text style={styles.noIdentityText}>
                            Create your Vouch identity to start signing content.
                        </Text>
                        <TouchableOpacity style={styles.createButton} onPress={handleCreateIdentity}>
                            <Text style={styles.createButtonText}>Create Identity</Text>
                        </TouchableOpacity>
                    </View>
                )}

                {/* Biometrics Info */}
                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>Security</Text>

                    <View style={styles.infoCard}>
                        <View style={styles.infoRow}>
                            <Text style={styles.infoLabel}>Biometry Available</Text>
                            <Text style={[styles.infoValue, biometrics?.available ? styles.green : styles.red]}>
                                {biometrics?.available ? 'Yes' : 'No'}
                            </Text>
                        </View>
                        <View style={styles.infoRow}>
                            <Text style={styles.infoLabel}>Type</Text>
                            <Text style={styles.infoValue}>{biometrics?.biometryType || 'None'}</Text>
                        </View>
                        <View style={styles.infoRow}>
                            <Text style={styles.infoLabel}>Security Level</Text>
                            <Text style={styles.infoValue}>{biometrics?.level || 'none'}</Text>
                        </View>
                    </View>
                </View>

                {/* Keys */}
                <View style={styles.section}>
                    <View style={styles.sectionHeader}>
                        <Text style={styles.sectionTitle}>Keys</Text>
                        {identity && (
                            <TouchableOpacity onPress={handleCreateAgent}>
                                <Text style={styles.addButton}>+ Add Agent</Text>
                            </TouchableOpacity>
                        )}
                    </View>

                    {keys.length === 0 ? (
                        <Text style={styles.emptyText}>No keys stored</Text>
                    ) : (
                        keys.map((key) => (
                            <View key={key.keyId} style={styles.keyCard}>
                                <View style={styles.keyInfo}>
                                    <Text style={styles.keyName}>
                                        {key.metadata?.name || 'Unnamed Key'}
                                    </Text>
                                    <Text style={styles.keyMeta}>
                                        {key.metadata?.type === 'root' ? '🔑 Root' : '👻 Agent'} •{' '}
                                        {key.algorithm} • Created {formatDate(key.createdAt)}
                                    </Text>
                                    <Text style={styles.keyId}>
                                        {key.keyId.slice(0, 8)}...{key.keyId.slice(-4)}
                                    </Text>
                                </View>
                                <TouchableOpacity
                                    onPress={() => handleDeleteKey(key.keyId, key.metadata?.name)}
                                    style={styles.deleteButton}
                                >
                                    <Text style={styles.deleteText}>🗑️</Text>
                                </TouchableOpacity>
                            </View>
                        ))
                    )}
                </View>

                {/* Export Section */}
                {identity && (
                    <View style={styles.section}>
                        <Text style={styles.sectionTitle}>Export</Text>
                        <TouchableOpacity style={styles.exportButton}>
                            <Text style={styles.exportButtonText}>📤 Export Public Key</Text>
                        </TouchableOpacity>
                        <Text style={styles.exportHint}>
                            Share your public key with others to receive verified content
                        </Text>
                    </View>
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
    content: {
        flex: 1,
        padding: 20,
    },
    identityCard: {
        backgroundColor: 'rgba(99, 102, 241, 0.15)',
        borderRadius: 16,
        padding: 20,
        marginBottom: 24,
        borderWidth: 1,
        borderColor: 'rgba(99, 102, 241, 0.3)',
    },
    identityHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 16,
    },
    identityIndicator: {
        width: 12,
        height: 12,
        borderRadius: 6,
        backgroundColor: '#10b981',
        marginRight: 8,
    },
    identityTitle: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    didContainer: {
        backgroundColor: 'rgba(0, 0, 0, 0.3)',
        borderRadius: 8,
        padding: 12,
        marginBottom: 16,
    },
    didLabel: {
        color: '#a0a0b0',
        fontSize: 11,
        marginBottom: 4,
    },
    didValue: {
        color: '#ffffff',
        fontSize: 12,
        fontFamily: 'monospace',
        lineHeight: 18,
    },
    didHint: {
        color: '#6366f1',
        fontSize: 11,
        marginTop: 8,
    },
    identityMeta: {
        flexDirection: 'row',
        gap: 24,
    },
    metaItem: {},
    metaLabel: {
        color: '#a0a0b0',
        fontSize: 12,
        marginBottom: 2,
    },
    metaValue: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '500',
    },
    noIdentityCard: {
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 16,
        padding: 24,
        marginBottom: 24,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    noIdentityTitle: {
        color: '#ffffff',
        fontSize: 18,
        fontWeight: '600',
        marginBottom: 8,
    },
    noIdentityText: {
        color: '#a0a0b0',
        fontSize: 14,
        textAlign: 'center',
        marginBottom: 20,
    },
    createButton: {
        backgroundColor: '#6366f1',
        paddingHorizontal: 24,
        paddingVertical: 12,
        borderRadius: 12,
    },
    createButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    section: {
        marginBottom: 24,
    },
    sectionHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 12,
    },
    sectionTitle: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
        marginBottom: 12,
    },
    addButton: {
        color: '#6366f1',
        fontSize: 14,
        fontWeight: '500',
    },
    infoCard: {
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 12,
        padding: 16,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    infoRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 12,
    },
    infoLabel: {
        color: '#a0a0b0',
        fontSize: 14,
    },
    infoValue: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '500',
    },
    green: {
        color: '#10b981',
    },
    red: {
        color: '#ef4444',
    },
    emptyText: {
        color: '#666',
        fontSize: 14,
    },
    keyCard: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    keyInfo: {
        flex: 1,
    },
    keyName: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '600',
        marginBottom: 4,
    },
    keyMeta: {
        color: '#a0a0b0',
        fontSize: 12,
        marginBottom: 4,
    },
    keyId: {
        color: '#666',
        fontSize: 11,
        fontFamily: 'monospace',
    },
    deleteButton: {
        padding: 8,
    },
    deleteText: {
        fontSize: 18,
    },
    exportButton: {
        backgroundColor: 'rgba(255, 255, 255, 0.1)',
        borderRadius: 12,
        padding: 16,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.2)',
    },
    exportButtonText: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '500',
    },
    exportHint: {
        color: '#666',
        fontSize: 12,
        textAlign: 'center',
        marginTop: 8,
    },
});
