# Vouch Verify Demo

AI-powered media verification using Gemini 3 + C2PA + Proof of Unique Moment.

## Features

- 🤖 **Deepfake Detection** - Gemini 3 analyzes images for manipulation artifacts
- 📜 **C2PA Verification** - Check for Content Credentials provenance chain
- 🌍 **Proof of Unique Moment** - Environmental attestation (weather, GPS, WiFi)
- 📊 **Trust Score** - Combined authenticity score (0-100%)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set your Gemini API key
export GEMINI_API_KEY=your_key_here

# Run the demo
streamlit run app.py
```

## Free Tier

- 5 verifications per day
- Basic C2PA + AI analysis
- [Upgrade to Pro](https://vouch-protocol.com/pro) for unlimited

## API Keys Required

1. **Gemini API Key** (required for AI analysis)
   - Get from: https://makersuite.google.com/app/apikey

2. **OpenWeather API Key** (optional, for environmental verification)
   - Get from: https://openweathermap.org/api

## For Hackathon Submission

This demo is built for the **Gemini 3 Hackathon** on Devpost.

Key Gemini 3 features used:
- Multimodal image analysis
- Deepfake/manipulation detection
- Structured output parsing
