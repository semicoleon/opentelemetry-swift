/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import Foundation

/// Keys used by Opentelemetry to store values in the Context
public enum OpenTelemetryContextKeys: String {
    case span
    case baggage
}

public struct OpenTelemetryContextProvider {
    var contextManager: ContextManager

    /// Returns the Span from the current context
    public var activeSpan: Span? {
        return contextManager.getCurrentContextValue(forKey: .span) as? Span
    }

    /// Returns the Baggage from the current context
    public var activeBaggage: Baggage? {
        return contextManager.getCurrentContextValue(forKey: OpenTelemetryContextKeys.baggage) as? Baggage
    }

    /// Attempts to set the active span manually. This will fail if the current context manager only supports closure based context.
    ///
    /// Prefer the closure based `withActive...` methods when possible, as they support any context manager.
    ///
    /// - Returns: `true` if the set was successful, `false` if the manager doesn't support the operation
    public func trySetActiveSpan(_ span: Span) -> Bool {
        guard let contextManager = contextManager as? ManualContextManager else {
            return false
        }

        contextManager.setCurrentContextValue(forKey: .span, value: span)
        return true
    }

    /// Attempts to remove the active span manually. This will fail if the current context manager only supports closure based context.
    ///
    /// Prefer the closure based `withActive...` methods when possible, as they support any context manager.
    ///
    /// - Returns: `true` if the removal was successful, `false` if the manager doesn't support the operation
    public func tryRemoveContextForSpan(_ span: Span) -> Bool {
        guard let contextManager = contextManager as? ManualContextManager else {
            return false
        }

        contextManager.removeContextValue(forKey: .span, value: span)
        return true
    }

    /// Attempts to set the active baggage manually. This will fail if the current context manager only supports closure based context.
    ///
    /// Prefer the closure based `withActive...` methods when possible, as they support any context manager.
    ///
    /// - Returns: `true` if the set was successful, `false` if the manager doesn't support the operation
    public func trySetActiveBaggage(_ baggage: Baggage) -> Bool {
        guard let contextManager = contextManager as? ManualContextManager else {
            return false
        }

        contextManager.setCurrentContextValue(forKey: .baggage, value: baggage)
        return true
    }

    /// Attempts to set the active baggage manually. This will fail if the current context manager only supports closure based context.
    ///
    /// Prefer the closure based `withActive...` methods when possible, as they support any context manager.
    ///
    /// - Returns: `true` if the remove was successful, `false` if the manager doesn't support the operation
    public func tryRemoveContextForBaggage(_ baggage: Baggage) -> Bool {
        guard let contextManager = contextManager as? ManualContextManager else {
            return false
        }

        contextManager.removeContextValue(forKey: .baggage, value: baggage)
        return true
    }

    /// Sets the given span as active for the duration of the closure
    @discardableResult
    public func withActiveSpan<T>(_ span: Span, _ action: () throws -> T) rethrows -> T {
        try contextManager.withActiveContext(key: .span, value: span, action)
    }

    /// Sets the given span as active for the duration of the closure
    @available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
    @discardableResult
    public func withActiveSpan<T>(_ span: Span, _ action: () async throws -> T) async rethrows -> T {
        try await contextManager.withActiveContext(key: .span, value: span, action)
    }

    /// Sets the given baggage as active for the duration of the closure
    @discardableResult
    public func withActiveBaggage<T>(_ baggage: Baggage, _ action: () throws -> T) rethrows -> T {
        try contextManager.withActiveContext(key: .baggage, value: baggage, action)
    }

    /// Sets the given baggage as active for the duration of the closure
    @available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
    @discardableResult
    public func withActiveBaggage<T>(_ baggage: Baggage, _ action: () async throws -> T) async rethrows -> T {
        try await contextManager.withActiveContext(key: .baggage, value: baggage, action)
    }
}

enum OpenTelemetryContextError: Error {
    case manualMethodCalledOnInvalidManager
}
