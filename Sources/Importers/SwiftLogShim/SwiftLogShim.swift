//
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
// 

import Foundation
import OpenTelemetryApi
import Logging

extension LoggerProvider {

    /// Create a `swift-log` handler from this `LoggerProvider`.
    /// - Parameters:
    ///   - label: The `swift-log` label the logger should use
    ///   - level: The log level as defined by `swift-log`
    ///   - encoder: A `JSONEncoder` which is used to encode complex metadata values that are supported by `swift-log` but not OpenTelemetry
    ///   - metadataProvider: The metadata provider configured via `swift-log`
    ///   - additionalMetadata: A type to provide additional metadata based on contextual information provided by `swift-log`. By default, a no-op implementation will be used.
    ///   - withBuilder: A closure which accepts a `LoggerBuilder` and applies additional configuration to it. By default no additional configuration will be performed
    /// - Returns: A log handler ready for use via `swift-log`
    public func swiftLogHandler<T: AdditionalMetadata>(
        label: String,
        level: Logging.Logger.Level,
        encoder: JSONEncoder,
        metadataProvider: Logging.Logger.MetadataProvider? = nil,
        additionalMetadata: T = NoAdditionalMetadata(),
        withBuilder: (LoggerBuilder) -> Void = { _ in }
    ) -> OpenTelemetrySwiftLog<T> {
        let builder = self.loggerBuilder(instrumentationScopeName: label)
        withBuilder(builder)

        return OpenTelemetrySwiftLog(
            logLevel: level,
            metadataProvider: metadataProvider,
            additionalMetadata: additionalMetadata,
            logger: builder.build(),
            encoder: encoder,
            label: label
        )
    }
}

extension Logging.Logger.MetadataProvider {
    /// Create a metadata provider that applies a closure to a span context to produce additional metadata for a log.
    ///
    /// This is useful for correlating logs with spans if your log ingress process doesn't maintain the correlation provided by the OpenTelemetry API.
    public static func openTelemetry(_ provider: @escaping (SpanContext?) -> Logging.Logger.Metadata) -> Self {
        Self {
            provider(OpenTelemetry.instance.contextProvider.activeSpan?.context)
        }
    }
}

/// A type which can modify the final metadata for a log before it is sent through to OpenTelemetry.
public protocol AdditionalMetadata {
    func updateMetadata(
        _ metadata: inout [String: AttributeValue],
        level: Logging.Logger.Level,
        label: String,
        message: Logging.Logger.Message,
        source: String,
        file: String,
        function: String,
        line: UInt
    )
}

/// The default `AdditionalMetadata` type, which adds no metadata to logs.
public struct NoAdditionalMetadata: AdditionalMetadata {
    public init() { }

    public func updateMetadata(
        _ metadata: inout [String: AttributeValue],
        level: Logging.Logger.Level,
        label: String,
        message: Logging.Logger.Message,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) { }
}

/// A `LogHandler` which directs logs to the configured OpenTelemetry logger
public struct OpenTelemetrySwiftLog<T: AdditionalMetadata>: LogHandler {
    internal init(
        logLevel: Logging.Logger.Level = .info,
        metadata: Logging.Logger.Metadata = Logging.Logger.Metadata(),
        metadataProvider: Logging.Logger.MetadataProvider? = nil,
        additionalMetadata: T,
        logger: OpenTelemetryApi.Logger,
        encoder: JSONEncoder,
        label: String
    ) {
        self.logLevel = logLevel
        self.metadata = metadata
        self.metadataProvider = metadataProvider
        self.additionalMetadata = additionalMetadata
        self.logger = logger
        self.encoder = encoder
        self.label = label
    }

    public var logLevel: Logging.Logger.Level = .info

    public var metadata = Logging.Logger.Metadata()
    public var metadataProvider: Logging.Logger.MetadataProvider?
    private let additionalMetadata: T
    private let logger: OpenTelemetryApi.Logger
    private let encoder: JSONEncoder
    private let label: String

    public subscript(metadataKey metadataKey: String) -> Logging.Logger.Metadata.Value? {
        get {
            metadata[metadataKey]
        }
        set {
            metadata[metadataKey] = newValue
        }
    }

    public func log(
        level: Logging.Logger.Level,
        message: Logging.Logger.Message,
        metadata: Logging.Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        var resolvedMetadata = Self.resolveMetadata(
            self.metadata,
            provider: metadataProvider,
            log: metadata,
            encoder: self.encoder
        ) ?? [:]

        self.additionalMetadata.updateMetadata(
            &resolvedMetadata,
            level: level,
            label: self.label,
            message: message,
            source: source,
            file: file,
            function: function,
            line: line
        )

        self.logger.logRecordBuilder()
            .setBody(.string(message.description))
            .setSeverity(level.toOtlp())
            .setAttributes(resolvedMetadata)
            .emit()
    }

    private static func resolveMetadata(
        _ metadata: Logging.Logger.Metadata,
        provider: Logging.Logger.MetadataProvider?,
        log: Logging.Logger.Metadata?,
        encoder: JSONEncoder
    ) -> [String: AttributeValue]? {
        var metadata = metadata

        if let provider {
            metadata.merge(provider.get()) { _, new in new }
        }

        if let log {
            metadata.merge(log) { _, new in new }
        }

        return metadata.mapValues { value in
            value.toOtlp(encoder: encoder)
        }
    }
}

extension Logging.Logger.MetadataValue: Encodable {
    func toOtlp(encoder: JSONEncoder) -> AttributeValue {
        switch self {

        case .string(let value):
            return .string(value)
        case .stringConvertible(let value):
            return .string(value.description)
        case .dictionary:
            return .string(self.forceStringRepresentation(encoder: encoder))
        case .array(let array):
            return .stringArray(array.map {
                guard let string = $0.toOtlpString() else {
                    return $0.forceStringRepresentation(encoder: encoder)
                }

                return string
            })
        }
    }

    func forceStringRepresentation(encoder: JSONEncoder) -> String {
        (try? encoder.encode(self))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "Failed to encode complex value"
    }

    func toOtlpString() -> String? {
        switch self {
        case .string(let value):
            return value
        case .stringConvertible(let value):
            return value.description
        case .dictionary:
            return nil
        case .array:
            return nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch self {
        case .string(let string):
            try container.encode(string)
        case .stringConvertible(let value):
            try container.encode(value.description)
        case .dictionary(let metadata):
            try container.encode(metadata)
        case .array(let array):
            try container.encode(array)
        }
    }
}

extension Logging.Logger.Level {
    func toOtlp() -> Severity {
        switch self {
        case .trace:
            return .trace
        case .debug:
            return .debug
        case .info:
            return .info
        case .notice:
            return .info2
        case .warning:
            return .warn
        case .error:
            return .error
        case .critical:
            return .error2
        }
    }
}
