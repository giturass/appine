package io.github.mthli.appine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VtRendererTest {
    @Test
    fun concealSkipsTheForegroundForEveryDecorationAndSearchMark() {
        val conceal = 1 shl 5
        for (underline in 0..5) {
            for (strikeAndOverline in 0..3) {
                for (mark in 0..2) {
                    val attrs = (underline shl 8) or (strikeAndOverline shl 6) or (mark shl 14)
                    assertTrue(VtRenderer.drawsForeground(attrs))
                    assertFalse(VtRenderer.drawsForeground(attrs or conceal))
                }
            }
        }
    }
}
