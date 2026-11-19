package io.github.mthli.appine

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.graphics.drawable.InsetDrawable
import android.graphics.drawable.RippleDrawable
import android.net.Uri
import android.text.SpannableString
import android.text.Spanned
import android.text.TextUtils
import android.text.style.TypefaceSpan
import android.view.View
import android.widget.ImageView
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.AppCompatImageButton
import androidx.core.graphics.ColorUtils
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.MaterialShapeDrawable
import com.google.android.material.shape.ShapeAppearanceModel
import kotlin.math.max

// Small helpers the app's screens and views share (the android/terminal map): sizes in dp and
// the theme's colours and drawables

/**
 * How thick the app's thin lines are (dp): the indicator under the tab bar's and the extra keys'
 * labels, and the terminal's progress line.
 */
internal const val LINE_DP = 1

/** [v] dp in whole pixels, rounded down. */
internal fun Context.dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

internal fun View.dp(v: Int): Int = context.dp(v)

/** [LINE_DP] in whole pixels, at least one. */
internal fun Context.line(): Int = max(1, dp(LINE_DP))

internal fun View.line(): Int = context.line()

/** The theme's colour [attr], white when the theme has none. */
internal fun Context.themeColor(attr: Int): Int = MaterialColors.getColor(this, attr, Color.WHITE)

internal fun View.themeColor(attr: Int): Int = context.themeColor(attr)

/** Selected controls use the text role paired with their filled primary container. */
internal fun View.terminalControlColor(selected: Boolean): Int = if (selected) {
    themeColor(com.google.android.material.R.attr.colorOnPrimaryContainer)
} else {
    themeColor(com.google.android.material.R.attr.colorOnSurfaceVariant)
}

/** Inset shapes leave space between controls without shrinking their touch targets. */
internal fun View.terminalControlBackground(tonal: Boolean = false, prominent: Boolean = false): Drawable {
    val shape = ShapeAppearanceModel.builder().setAllCornerSizes(dp(12).toFloat()).build()
    val active = themeColor(com.google.android.material.R.attr.colorPrimaryContainer)
    val normal = when {
        prominent -> themeColor(androidx.appcompat.R.attr.colorPrimary)
        tonal -> themeColor(com.google.android.material.R.attr.colorSurfaceContainerHigh)
        else -> Color.TRANSPARENT
    }
    val colors = ColorStateList(
        arrayOf(intArrayOf(android.R.attr.state_selected), intArrayOf(android.R.attr.state_activated), intArrayOf()),
        intArrayOf(active, active, normal),
    )
    val content = MaterialShapeDrawable(shape).apply { fillColor = colors }
    val mask = MaterialShapeDrawable(shape).apply { fillColor = ColorStateList.valueOf(Color.WHITE) }
    val ripple = ColorUtils.setAlphaComponent(themeColor(com.google.android.material.R.attr.colorOnSurface), 32)
    return InsetDrawable(RippleDrawable(ColorStateList.valueOf(ripple), content, mask), dp(4))
}

internal fun Context.terminalIconButton(
    @DrawableRes icon: Int,
    @StringRes description: Int,
    prominent: Boolean = false,
    onClick: (View) -> Unit,
) = AppCompatImageButton(this).apply {
    setImageResource(icon)
    contentDescription = getString(description)
    tooltipText = contentDescription
    imageTintList = if (prominent) {
        ColorStateList.valueOf(themeColor(com.google.android.material.R.attr.colorOnPrimary))
    } else {
        ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_selected), intArrayOf()),
            intArrayOf(terminalControlColor(selected = true), terminalControlColor(selected = false)),
        )
    }
    scaleType = ImageView.ScaleType.CENTER_INSIDE
    background = terminalControlBackground(prominent = prominent)
    setPadding(dp(12), dp(12), dp(12), dp(12))
    setOnClickListener {
        it.performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP)
        onClick(it)
    }
}

/** The theme's drawable [attr], null when the theme has none. */
internal fun Context.themeDrawable(attr: Int): Drawable? {
    val a = obtainStyledAttributes(intArrayOf(attr))
    try {
        return a.getDrawable(0)
    } finally {
        a.recycle()
    }
}

/** The theme's ripple for something that can be tapped. */
internal fun View.touchFeedback(): Drawable? = context.themeDrawable(android.R.attr.selectableItemBackground)

/** Opens a system settings action that takes the app's package URI. */
internal fun Activity.openPackageSettings(action: String) {
    startActivity(Intent(action, Uri.fromParts("package", packageName, null)))
}

/** Inserts a monospace value at the localized message's ^1 placeholder, preserving its span. */
internal fun Context.monospaceMessage(@StringRes template: Int, value: String): CharSequence {
    val content = SpannableString(value).apply {
        setSpan(TypefaceSpan("monospace"), 0, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }
    return TextUtils.expandTemplate(getText(template), content)
}

/** Dialog windows do not inherit FLAG_SECURE from their activity. */
internal fun MaterialAlertDialogBuilder.showPrivate(): AlertDialog = create().also {
    Privacy.protect(it)
    it.show()
}
