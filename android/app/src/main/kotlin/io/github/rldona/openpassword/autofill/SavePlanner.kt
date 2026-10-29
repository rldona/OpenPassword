package io.github.rldona.openpassword.autofill

/** Whether saving a typed login should create an item or update an existing one. */
sealed interface SavePlan {
    data object New : SavePlan
    data class Update(val entryId: String) : SavePlan
}

object SavePlanner {
    /**
     * [candidates] are logins that already match the target, with their stored username.
     * Same username (ignoring case and spaces) means the user changed that account's
     * password: update it instead of creating a duplicate.
     */
    fun plan(candidates: List<Pair<String, String?>>, username: String): SavePlan {
        val typed = username.trim().lowercase()
        val match = candidates.firstOrNull { (_, stored) -> stored?.trim()?.lowercase() == typed }
        return match?.let { SavePlan.Update(it.first) } ?: SavePlan.New
    }

    /** Website URL or app link to store for a new login. */
    fun urlFor(target: FillTarget): String = when (target) {
        is FillTarget.Web -> "https://${target.domain.trim().trimEnd('.')}"
        is FillTarget.App -> LoginMatcher.appUrl(target.packageName)
    }
}
