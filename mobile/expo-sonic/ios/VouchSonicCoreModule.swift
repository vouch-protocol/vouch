import ExpoModulesCore
import Foundation

// UniFFI-generated Swift API (SonicListener, SignatureVerifier,
// WatermarkCallback, WatermarkResult, SonicConfig, ListenerState, getVersion)
// is vendored under ios/uniffi/ and compiled into this same target.

/// JS-side config record mapped to the UniFFI `SonicConfig`.
struct SonicConfigRecord: Record {
  @Field var sampleRate: Int = 16000
  @Field var frameSizeMs: Int = 50
  @Field var detectionThreshold: Double = 0.5
  @Field var spreadingFactor: Int = 100
  @Field var enableChirpSync: Bool = true

  func toUniffi() -> SonicConfig {
    SonicConfig(
      sampleRate: UInt32(sampleRate),
      frameSizeMs: UInt32(frameSizeMs),
      detectionThreshold: Float(detectionThreshold),
      spreadingFactor: UInt32(spreadingFactor),
      enableChirpSync: enableChirpSync
    )
  }
}

/// Expo module exposing the Rust Sonic Core (UniFFI) to React Native under the
/// name "VouchSonicCore". Adapts the UniFFI object API to the flat,
/// handle-based contract the mobile host app expects; the UniFFI WatermarkCallback is
/// forwarded to RN as module events carrying the listenerId.
public final class VouchSonicCoreModule: Module {
  private var listeners = [String: SonicListener]()
  private let lock = NSLock()
  private lazy var verifier = SignatureVerifier()

  public func definition() -> ModuleDefinition {
    Name("VouchSonicCore")

    Events("onWatermark", "onAudioLevel", "onError", "onStateChange")

    AsyncFunction("getVersion") { () -> String in
      getVersion()
    }

    AsyncFunction("createListener") { (config: SonicConfigRecord) throws -> String in
      let listener = try SonicListener(config: config.toUniffi())
      let id = UUID().uuidString
      self.lock.lock(); self.listeners[id] = listener; self.lock.unlock()
      return id
    }

    AsyncFunction("startListening") { (listenerId: String) throws in
      let listener = try self.requireListener(listenerId)
      try listener.startListening(callback: SonicCallback(module: self, listenerId: listenerId))
    }

    AsyncFunction("stopListening") { (listenerId: String) throws in
      try self.requireListener(listenerId).stopListening()
    }

    AsyncFunction("processBuffer") { (listenerId: String, pcmDataB64: String) throws -> [String: Any?] in
      guard let data = Data(base64Encoded: pcmDataB64) else {
        throw Exception(name: "E_BAD_BASE64", description: "pcmData is not valid base64")
      }
      return try self.requireListener(listenerId).processBuffer(pcmData: [UInt8](data)).toDict()
    }

    AsyncFunction("processSamples") { (listenerId: String, samples: [Double]) throws -> [String: Any?] in
      try self.requireListener(listenerId).processSamples(samples: samples.map { Float($0) }).toDict()
    }

    AsyncFunction("getState") { (listenerId: String) throws -> String in
      try self.requireListener(listenerId).getState().toJs()
    }

    AsyncFunction("isListening") { (listenerId: String) throws -> Bool in
      try self.requireListener(listenerId).isListening()
    }

    AsyncFunction("setDetectionThreshold") { (listenerId: String, threshold: Double) throws in
      try self.requireListener(listenerId).setDetectionThreshold(threshold: Float(threshold))
    }

    AsyncFunction("disposeListener") { (listenerId: String) in
      self.lock.lock(); self.listeners.removeValue(forKey: listenerId); self.lock.unlock()
    }

    AsyncFunction("verifySignature") {
      (messageB64: String, signatureB64: String, publicKeyB64: String) throws -> [String: Any?] in
      guard let m = Data(base64Encoded: messageB64),
            let s = Data(base64Encoded: signatureB64),
            let p = Data(base64Encoded: publicKeyB64) else {
        throw Exception(name: "E_BAD_BASE64", description: "message/signature/publicKey must be base64")
      }
      return self.verifier
        .verifySignature(message: [UInt8](m), signature: [UInt8](s), publicKey: [UInt8](p))
        .toDict()
    }
  }

  /// Exposed so the callback class can emit module events.
  func emit(_ name: String, _ body: [String: Any?]) {
    sendEvent(name, body)
  }

  private func requireListener(_ id: String) throws -> SonicListener {
    lock.lock(); let listener = listeners[id]; lock.unlock()
    guard let l = listener else {
      throw Exception(name: "E_NO_LISTENER", description: "No SonicListener registered for id '\(id)'")
    }
    return l
  }
}

/// Bridges the UniFFI callback to RN module events tagged with the listenerId.
private final class SonicCallback: WatermarkCallback {
  weak var module: VouchSonicCoreModule?
  let listenerId: String

  init(module: VouchSonicCoreModule, listenerId: String) {
    self.module = module
    self.listenerId = listenerId
  }

  func onWatermarkDetected(result: WatermarkResult) {
    module?.emit("onWatermark", ["listenerId": listenerId, "result": result.toDict()])
  }
  func onAudioLevelChanged(levelDb: Float) {
    module?.emit("onAudioLevel", ["listenerId": listenerId, "levelDb": levelDb])
  }
  func onError(message: String) {
    module?.emit("onError", ["listenerId": listenerId, "message": message])
  }
  func onStateChanged(state: ListenerState) {
    module?.emit("onStateChange", ["listenerId": listenerId, "state": state.toJs()])
  }
}

// MARK: - conversion helpers

private extension ListenerState {
  func toJs() -> String {
    switch self {
    case .idle: return "Idle"
    case .listening: return "Listening"
    case .processing: return "Processing"
    case .error: return "Error"
    }
  }
}

private extension WatermarkResult {
  func toDict() -> [String: Any?] {
    return [
      "detected": detected,
      "confidence": confidence,
      "signerDid": signerDid as Any?,
      "timestamp": timestamp.map { Double($0) } as Any?,
      "payloadHash": payloadHash as Any?,
      "covenantJson": covenantJson as Any?,
      "audioQuality": audioQuality,
      "detectionMethod": detectionMethod,
    ]
  }
}

private extension VerificationResult {
  func toDict() -> [String: Any?] {
    return [
      "valid": valid,
      "signerDid": signerDid as Any?,
      "errorMessage": errorMessage as Any?,
    ]
  }
}
