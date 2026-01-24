/**
 * Root Layout - Expo Router layout configuration
 *
 * Configures the navigation stack and global providers.
 */

import React, { useEffect } from 'react';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { View, StyleSheet } from 'react-native';

// =============================================================================
// Root Layout
// =============================================================================

export default function RootLayout() {
    return (
        <View style={styles.container}>
            <StatusBar style="light" />
            <Stack
                screenOptions={{
                    headerShown: false,
                    contentStyle: { backgroundColor: '#0a0a0f' },
                    animation: 'slide_from_right',
                }}
            >
                <Stack.Screen name="index" />
                <Stack.Screen
                    name="verify"
                    options={{
                        animation: 'slide_from_bottom',
                    }}
                />
                <Stack.Screen
                    name="pair"
                    options={{
                        animation: 'slide_from_bottom',
                    }}
                />
                <Stack.Screen
                    name="identity"
                    options={{
                        animation: 'slide_from_right',
                    }}
                />
            </Stack>
        </View>
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
});
