package expo.modules.vouchsoniccore

import android.util.Base64
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// UniFFI-generated bindings (vendored under uniffi/vouch_sonic_core/).
import uniffi.vouch_sonic_core.ListenerState
import uniffi.vouch_sonic_core.SignatureVerifier
import uniffi.vouch_sonic_core.SonicConfig
import uniffi.vouch_sonic_core.SonicListener
import uniffi.vouch_sonic_core.WatermarkCallback
import uniffi.vouch_sonic_core.WatermarkResult
import uniffi.vouch_sonic_core.getVersion

/** JS-side config record mapped to the UniFFI `SonicConfig`. */
class SonicConfigRecord : Record {
  @Field var sampleRate: Int = 16000
  @Field var frameSizeMs: Int = 50
  @Field var detectionThreshold: Float = 0.5f
  @Field var spreadingFactor: Int = 100
  @Field var enableChirpSync: Boolean = true

  fun toUniffi(): SonicConfig = SonicConfig(
    sampleRate.toUInt(),
    frameSizeMs.toUInt(),
    detectionThreshold,
    spreadingFactor.toUInt(),
    enableChirpSync
  )
}

/**
 * Expo module that exposes the Rust Sonic Core (via UniFFI) to React Native
 * under the name "VouchSonicCore". It adapts the UniFFI object API to the
 * flat, handle-based contract expected by the mobile host app: a listenerId string
 * identifies a native SonicListener, and the UniFFI WatermarkCallback is
 * forwarded to RN as module events carrying that listenerId.
 */
class VouchSonicCoreModule : Module() {
  private val listeners = ConcurrentHashMap<String, SonicListener>()
  private val verifier by lazy { SignatureVerifier() }

  override fun definition() = ModuleDefinition {
    Name("VouchSonicCore")

    Events("onWatermark", "onAudioLevel", "onError", "onStateChange")

    AsyncFunction("getVersion") {
      getVersion()
    }

    AsyncFunction("createListener") { config: SonicConfigRecord ->
      val listener = SonicListener(config.toUniffi())
      val id = UUID.randomUUID().toString()
      listeners[id] = listener
      id
    }

    AsyncFunction("startListening") { listenerId: String ->
      requireListener(listenerId).startListening(makeCallback(listenerId))
    }

    AsyncFunction("stopListening") { listenerId: String ->
      requireListener(listenerId).stopListening()
    }

    AsyncFunction("processBuffer") { listenerId: String, pcmDataB64: String ->
      val pcm = Base64.decode(pcmDataB64, Base64.DEFAULT).toUByteList()
      requireListener(listenerId).processBuffer(pcm).toJsMap()
    }

    AsyncFunction("processSamples") { listenerId: String, samples: List<Double> ->
      requireListener(listenerId).processSamples(samples.map { it.toFloat() }).toJsMap()
    }

    AsyncFunction("getState") { listenerId: String ->
      requireListener(listenerId).getState().toJs()
    }

    AsyncFunction("isListening") { listenerId: String ->
      requireListener(listenerId).isListening()
    }

    AsyncFunction("setDetectionThreshold") { listenerId: String, threshold: Double ->
      requireListener(listenerId).setDetectionThreshold(threshold.toFloat())
    }

    AsyncFunction("disposeListener") { listenerId: String ->
      listeners.remove(listenerId)?.let { listener ->
        runCatching { listener.stopListening() }
        listener.close()
      }
      Unit
    }

    AsyncFunction("verifySignature") {
      messageB64: String, signatureB64: String, publicKeyB64: String ->
      verifier.verifySignature(
        Base64.decode(messageB64, Base64.DEFAULT).toUByteList(),
        Base64.decode(signatureB64, Base64.DEFAULT).toUByteList(),
        Base64.decode(publicKeyB64, Base64.DEFAULT).toUByteList()
      ).toJsMap()
    }

    OnDestroy {
      listeners.values.forEach { runCatching { it.close() } }
      listeners.clear()
    }
  }

  private fun requireListener(id: String): SonicListener =
    listeners[id] ?: throw CodedException(
      "E_NO_LISTENER", "No SonicListener registered for id '$id'", null
    )

  private fun makeCallback(listenerId: String): WatermarkCallback =
    object : WatermarkCallback {
      override fun onWatermarkDetected(result: WatermarkResult) {
        sendEvent("onWatermark", mapOf("listenerId" to listenerId, "result" to result.toJsMap()))
      }
      override fun onAudioLevelChanged(levelDb: Float) {
        sendEvent("onAudioLevel", mapOf("listenerId" to listenerId, "levelDb" to levelDb))
      }
      override fun onError(message: String) {
        sendEvent("onError", mapOf("listenerId" to listenerId, "message" to message))
      }
      override fun onStateChanged(state: ListenerState) {
        sendEvent("onStateChange", mapOf("listenerId" to listenerId, "state" to state.toJs()))
      }
    }
}

// ---- conversion helpers ----------------------------------------------------

private fun ByteArray.toUByteList(): List<UByte> = map { it.toUByte() }

private fun ListenerState.toJs(): String = when (this) {
  ListenerState.IDLE -> "Idle"
  ListenerState.LISTENING -> "Listening"
  ListenerState.PROCESSING -> "Processing"
  ListenerState.ERROR -> "Error"
}

private fun WatermarkResult.toJsMap(): Map<String, Any?> = mapOf(
  "detected" to detected,
  "confidence" to confidence,
  "signerDid" to signerDid,
  "timestamp" to timestamp?.toLong(),
  "payloadHash" to payloadHash,
  "covenantJson" to covenantJson,
  "audioQuality" to audioQuality,
  "detectionMethod" to detectionMethod
)

private fun uniffi.vouch_sonic_core.VerificationResult.toJsMap(): Map<String, Any?> = mapOf(
  "valid" to valid,
  "signerDid" to signerDid,
  "errorMessage" to errorMessage
)
