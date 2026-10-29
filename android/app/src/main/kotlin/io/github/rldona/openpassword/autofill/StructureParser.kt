package io.github.rldona.openpassword.autofill

import android.app.assist.AssistStructure
import android.view.View
import android.view.autofill.AutofillId

/** The login fields found on screen and who is asking. */
data class LoginRequest(val target: FillTarget, val username: AutofillId?, val password: AutofillId?) {
    val ids: List<AutofillId> get() = listOfNotNull(username, password)
}

object StructureParser {
    /** Null if there is nothing to fill, or the request comes from OpenPassword itself. */
    fun parse(structure: AssistStructure, ownPackage: String): LoginRequest? {
        val packageName = structure.activityComponent?.packageName ?: return null
        if (packageName == ownPackage) return null

        var webDomain: String? = null
        val fields = mutableListOf<Pair<AutofillId, FieldType?>>()

        fun visit(node: AssistStructure.ViewNode) {
            if (webDomain == null) node.webDomain?.takeIf(String::isNotBlank)?.let { webDomain = it }
            val id = node.autofillId
            if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE) {
                val signals = FieldSignals(
                    autofillHints = node.autofillHints?.toList().orEmpty(),
                    inputType = node.inputType,
                    htmlAttributes = node.htmlInfo?.attributes?.map { it.first.orEmpty() to it.second.orEmpty() }.orEmpty(),
                    texts = listOfNotNull(node.idEntry, node.hint, node.contentDescription?.toString()),
                    isEditable = node.isEnabled,
                )
                fields += id to FieldClassifier.classify(signals)
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)

        val (username, password) = pickLoginFields(fields)
        if (username == null && password == null) return null
        val target = webDomain?.let { FillTarget.Web(it) } ?: FillTarget.App(packageName)
        return LoginRequest(target, username, password)
    }
}
