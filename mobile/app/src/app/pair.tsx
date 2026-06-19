/**
 * Pair Screen - Desktop Bridge Pairing
 *
 * Scans QR code from desktop Vouch Bridge to establish
 * secure connection for remote signing.
 */

import React, { useState, useCallback, useEffect } from 'react';
import {
    View,
    Text,
    TouchableOpacity,
    StyleSheet,
    SafeAreaView,
    StatusBar,
    Alert,
} from 'react-native';
import { router } from 'expo-router';
import { CameraView, useCameraPermissions } from 'expo-camera';

// =============================================================================
// Types
// =============================================================================

interface PairedDevice {
    bridgeId: string;
    name: string;
    publicKey: string;
    pairedAt: Date;
    lastActive: Date;
}

interface BridgeQRData {
    bridgeId: string;
    sessionNonce: string;
    wsEndpoint: string;
    publicKey: string;
    name?: string;
}

// =============================================================================
// Pair Screen
// =============================================================================

export default function PairScreen() {
    const [permission, requestPermission] = useCameraPermissions();
    const [scanning, setScanning] = useState(false);
    const [pairedDevices, setPairedDevices] = useState<PairedDevice[]>([]);

    // Handle QR code scan
    const handleBarcodeScanned = useCallback(({ data }: { data: string }) => {
        if (!scanning) return;
        setScanning(false);

        try {
            const qrData: BridgeQRData = JSON.parse(data);

            if (!qrData.bridgeId || !qrData.wsEndpoint) {
                Alert.alert('Invalid QR Code', 'This is not a valid Vouch Bridge QR code.');
                return;
            }

            // TODO: Establish WebSocket connection and ECDH key exchange
            Alert.alert(
                'Device Found',
                `Found: ${qrData.name || 'Desktop Bridge'}\n\nEstablish secure connection?`,
                [
                    { text: 'Cancel', style: 'cancel' },
                    {
                        text: 'Connect',
                        onPress: () => handleConnect(qrData),
                    },
                ]
            );
        } catch {
            Alert.alert('Invalid QR Code', 'Could not parse QR code data.');
        }
    }, [scanning]);

    // Handle connection
    const handleConnect = useCallback(async (qrData: BridgeQRData) => {
        // TODO: Implement WebSocket connection
        const newDevice: PairedDevice = {
            bridgeId: qrData.bridgeId,
            name: qrData.name || 'Desktop Bridge',
            publicKey: qrData.publicKey,
            pairedAt: new Date(),
            lastActive: new Date(),
        };

        setPairedDevices((prev) => [...prev, newDevice]);
        Alert.alert('Success', `Connected to ${newDevice.name}!`);
    }, []);

    // Handle disconnect
    const handleDisconnect = useCallback((bridgeId: string) => {
        Alert.alert(
            'Disconnect',
            'Are you sure you want to disconnect this device?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Disconnect',
                    style: 'destructive',
                    onPress: () => {
                        setPairedDevices((prev) => prev.filter((d) => d.bridgeId !== bridgeId));
                    },
                },
            ]
        );
    }, []);

    // Request camera permission
    if (!permission) {
        return null;
    }

    if (!permission.granted) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar barStyle="light-content" />
                <View style={styles.permissionContainer}>
                    <Text style={styles.permissionTitle}>📷 Camera Access Needed</Text>
                    <Text style={styles.permissionText}>
                        Vouch Verifier needs camera access to scan QR codes for desktop pairing.
                    </Text>
                    <TouchableOpacity style={styles.permissionButton} onPress={requestPermission}>
                        <Text style={styles.permissionButtonText}>Grant Permission</Text>
                    </TouchableOpacity>
                </View>
            </SafeAreaView>
        );
    }

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar barStyle="light-content" />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <Text style={styles.backText}>← Back</Text>
                </TouchableOpacity>
                <Text style={styles.title}>🔗 Pair with Desktop</Text>
            </View>

            {/* Scanner */}
            {scanning ? (
                <View style={styles.scannerContainer}>
                    <CameraView
                        style={styles.camera}
                        barcodeScannerSettings={{
                            barcodeTypes: ['qr'],
                        }}
                        onBarcodeScanned={handleBarcodeScanned}
                    />
                    <View style={styles.scannerOverlay}>
                        <View style={styles.scannerFrame} />
                        <Text style={styles.scannerText}>
                            Scan the QR code from Vouch Bridge
                        </Text>
                    </View>
                    <TouchableOpacity
                        style={styles.cancelButton}
                        onPress={() => setScanning(false)}
                    >
                        <Text style={styles.cancelButtonText}>Cancel</Text>
                    </TouchableOpacity>
                </View>
            ) : (
                <View style={styles.content}>
                    {/* Scan Button */}
                    <TouchableOpacity
                        style={styles.scanButton}
                        onPress={() => setScanning(true)}
                    >
                        <Text style={styles.scanButtonEmoji}>📷</Text>
                        <Text style={styles.scanButtonText}>Scan QR Code</Text>
                        <Text style={styles.scanButtonSubtext}>
                            Open Vouch Bridge on your computer and scan the QR code
                        </Text>
                    </TouchableOpacity>

                    {/* Paired Devices */}
                    <View style={styles.devicesSection}>
                        <Text style={styles.devicesTitle}>Paired Devices</Text>

                        {pairedDevices.length === 0 ? (
                            <Text style={styles.emptyText}>No devices paired yet</Text>
                        ) : (
                            pairedDevices.map((device) => (
                                <View key={device.bridgeId} style={styles.deviceCard}>
                                    <View style={styles.deviceInfo}>
                                        <View style={styles.deviceIndicator} />
                                        <View>
                                            <Text style={styles.deviceName}>{device.name}</Text>
                                            <Text style={styles.deviceMeta}>
                                                Paired {device.pairedAt.toLocaleDateString()}
                                            </Text>
                                        </View>
                                    </View>
                                    <TouchableOpacity
                                        style={styles.disconnectButton}
                                        onPress={() => handleDisconnect(device.bridgeId)}
                                    >
                                        <Text style={styles.disconnectText}>Disconnect</Text>
                                    </TouchableOpacity>
                                </View>
                            ))
                        )}
                    </View>

                    {/* Instructions */}
                    <View style={styles.instructions}>
                        <Text style={styles.instructionsTitle}>How to pair:</Text>
                        <Text style={styles.instructionsText}>
                            1. Run <Text style={styles.code}>vouch-bridge</Text> on your computer
                        </Text>
                        <Text style={styles.instructionsText}>
                            2. Open the web dashboard at <Text style={styles.code}>localhost:21000</Text>
                        </Text>
                        <Text style={styles.instructionsText}>
                            3. Click "Pair Mobile Device" and scan the QR code
                        </Text>
                    </View>
                </View>
            )}
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
    permissionContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 32,
    },
    permissionTitle: {
        fontSize: 24,
        fontWeight: '700',
        color: '#ffffff',
        marginBottom: 16,
    },
    permissionText: {
        color: '#a0a0b0',
        fontSize: 16,
        textAlign: 'center',
        marginBottom: 32,
    },
    permissionButton: {
        backgroundColor: '#6366f1',
        paddingHorizontal: 32,
        paddingVertical: 16,
        borderRadius: 12,
    },
    permissionButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    content: {
        flex: 1,
        padding: 20,
    },
    scannerContainer: {
        flex: 1,
    },
    camera: {
        flex: 1,
    },
    scannerOverlay: {
        ...StyleSheet.absoluteFillObject,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
    },
    scannerFrame: {
        width: 250,
        height: 250,
        borderWidth: 3,
        borderColor: '#6366f1',
        borderRadius: 16,
        marginBottom: 24,
    },
    scannerText: {
        color: '#ffffff',
        fontSize: 16,
    },
    cancelButton: {
        position: 'absolute',
        bottom: 40,
        left: 20,
        right: 20,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        paddingVertical: 16,
        borderRadius: 12,
        alignItems: 'center',
    },
    cancelButtonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
    },
    scanButton: {
        backgroundColor: 'rgba(139, 92, 246, 0.15)',
        borderWidth: 2,
        borderColor: '#8b5cf6',
        borderStyle: 'dashed',
        borderRadius: 20,
        padding: 32,
        alignItems: 'center',
        marginBottom: 32,
    },
    scanButtonEmoji: {
        fontSize: 48,
        marginBottom: 16,
    },
    scanButtonText: {
        color: '#ffffff',
        fontSize: 18,
        fontWeight: '700',
        marginBottom: 8,
    },
    scanButtonSubtext: {
        color: '#a0a0b0',
        fontSize: 14,
        textAlign: 'center',
    },
    devicesSection: {
        marginBottom: 32,
    },
    devicesTitle: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600',
        marginBottom: 12,
    },
    emptyText: {
        color: '#666',
        fontSize: 14,
    },
    deviceCard: {
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
    deviceInfo: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    deviceIndicator: {
        width: 10,
        height: 10,
        borderRadius: 5,
        backgroundColor: '#10b981',
        marginRight: 12,
    },
    deviceName: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '600',
    },
    deviceMeta: {
        color: '#666',
        fontSize: 12,
        marginTop: 2,
    },
    disconnectButton: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderRadius: 6,
        backgroundColor: 'rgba(239, 68, 68, 0.2)',
    },
    disconnectText: {
        color: '#ef4444',
        fontSize: 12,
        fontWeight: '500',
    },
    instructions: {
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 12,
        padding: 16,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    instructionsTitle: {
        color: '#ffffff',
        fontSize: 14,
        fontWeight: '600',
        marginBottom: 12,
    },
    instructionsText: {
        color: '#a0a0b0',
        fontSize: 13,
        marginBottom: 8,
        lineHeight: 20,
    },
    code: {
        fontFamily: 'monospace',
        color: '#6366f1',
        backgroundColor: 'rgba(99, 102, 241, 0.2)',
        paddingHorizontal: 4,
        borderRadius: 4,
    },
});
