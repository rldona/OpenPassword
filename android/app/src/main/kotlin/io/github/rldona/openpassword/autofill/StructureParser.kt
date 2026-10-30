package io.github.rldona.openpassword.autofill

import android.app.assist.AssistStructure
import android.view.View
import android.view.autofill.AutofillId

/** The login fields found on screen and who is asking. */
data class LoginRequest(val target: FillTarget, val username: AutofillId?, val password: AutofillId?) {
    val ids: List<AutofillId> get() = listOfNotNull(username, password)
}

private typealias ViewNode = AssistStructure.ViewNode

private fun AssistStructure.windowRoots(): List<ViewNode> = List(windowNodeCount) { getWindowNodeAt(it).rootViewNode }

object StructureParser {
    /** The text currently in the field [id], searching every screen of the request. */
    fun textValue(structures: List<AssistStructure>, id: AutofillId): String? {
        for (structure in structures.asReversed()) {
            var found: String? = null
            walkTree(structure.windowRoots(), { it.childCount }, { node, i -> node.getChildAt(i) }) { node ->
                if (node.autofillId != id) return@walkTree false
                found = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
                true
            }
            found?.let { return it }
        }
        return null
    }

    /** A claimed web domain is honoured only from a real browser; otherwise the request is about the app. */
    fun targetFor(packageName: String, webDomain: String?, browsers: BrowserCheck): FillTarget =
        if (webDomain != null && browsers.isBrowser(packageName)) FillTarget.Web(webDomain) else FillTarget.App(packageName)

    /** Null if there is nothing to fill, or the request comes from OpenPassword itself. */
    fun parse(structure: AssistStructure, ownPackage: String, browsers: BrowserCheck): LoginRequest? {
        val packageName = structure.activityComponent?.packageName ?: return null
        if (packageName == ownPackage) return null

        var webDomain: String? = null
        val fields = mutableListOf<Pair<AutofillId, FieldType?>>()

        walkTree(structure.windowRoots(), { it.childCount }, { node, i -> node.getChildAt(i) }) { node ->
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
            false
        }

        val (username, password) = pickLoginFields(fields)
        if (username == null && password == null) return null
        return LoginRequest(targetFor(packageName, webDomain, browsers), username, password)
    }
}
