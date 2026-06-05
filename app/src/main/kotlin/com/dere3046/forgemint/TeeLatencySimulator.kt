package com.dere3046.forgemint

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.SecurityLevel
import java.security.SecureRandom
import java.util.concurrent.locks.LockSupport
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max

object TeeLatencySimulator {

    private val rng = SecureRandom()
    private val sessionBiasMs: Double by lazy { rng.nextGaussian() * 5.0 }
    private val coldPenaltyMs: Double by lazy { abs(rng.nextGaussian() * 12.0) }

    @Volatile private var firstKeyGen = true
    @Volatile private var firstOp = true

    fun simulateGenerateKeyDelay(algorithm: Int, securityLevel: Int, elapsedNanos: Long) {
        val elapsedMs = elapsedNanos / 1_000_000.0
        val targetMs = computeGenerateKeyTarget(algorithm, securityLevel)
        val remainingMs = targetMs - elapsedMs
        if (remainingMs > 1.0) {
            LockSupport.parkNanos((remainingMs * 1_000_000).toLong())
        }
    }

    fun simulateOperationDelay(algorithm: Int, securityLevel: Int, elapsedNanos: Long) {
        val elapsedMs = elapsedNanos / 1_000_000.0
        val targetMs = computeOperationTarget(algorithm, securityLevel)
        val remainingMs = targetMs - elapsedMs
        if (remainingMs > 1.0) {
            LockSupport.parkNanos((remainingMs * 1_000_000).toLong())
        }
    }

    private fun computeGenerateKeyTarget(algorithm: Int, securityLevel: Int): Double {
        val floor = if (securityLevel == SecurityLevel.STRONGBOX) 250.0 else 15.0
        val base = when (algorithm) {
            Algorithm.EC -> ln(60.0) to 0.08
            Algorithm.RSA -> ln(70.0) to 0.08
            Algorithm.AES -> ln(35.0) to 0.10
            else -> ln(40.0) to 0.10
        }
        return computeTarget(floor, base.first, base.second, firstKeyGen)
    }

    private fun computeOperationTarget(algorithm: Int, securityLevel: Int): Double {
        val floor = if (securityLevel == SecurityLevel.STRONGBOX) 80.0 else 4.0
        val base = when (algorithm) {
            Algorithm.EC -> ln(30.0) to 0.10
            Algorithm.RSA -> ln(40.0) to 0.10
            Algorithm.AES -> ln(15.0) to 0.12
            else -> ln(20.0) to 0.12
        }
        return computeTarget(floor, base.first, base.second, firstOp)
    }

    private fun computeTarget(floor: Double, mu: Double, sigma: Double, firstFlag: Boolean): Double {
        val base = exp(mu + sigma * rng.nextGaussian())
        val transit = sampleExponential(2.5)
        val jitter = (rng.nextGaussian() * 2.5).coerceIn(-8.0, 12.0)
        var cold = 0.0
        if (firstFlag) {
            cold = coldPenaltyMs
        }
        return max(floor, base + transit + jitter + sessionBiasMs + cold)
    }

    private fun sampleExponential(mean: Double): Double {
        var u = rng.nextDouble()
        while (u == 0.0) u = rng.nextDouble()
        return -mean * ln(u)
    }
}
