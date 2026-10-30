package io.github.rldona.openpassword.autofill

/**
 * Limits for walking an `AssistStructure`, which the app being filled builds and so may be
 * hostile or just huge (ID-INT-18).
 *
 * - [MAX_DEPTH] = 100: real screens nest 20–40 levels, deep Compose and WebView content a
 *   few more; 100 leaves a wide margin and is far below the point where recursion would
 *   overflow the stack.
 * - [MAX_NODES] = 20,000: a very heavy web page is a few thousand nodes. Visiting a node
 *   costs microseconds and nothing is kept per node, so this bounds time and memory
 *   (the work stack never holds more than this many entries) without cutting real forms.
 *
 * Both are cut-offs, not errors: what was found before the limit is still used.
 */
object TreeLimits {
    const val MAX_DEPTH = 100
    const val MAX_NODES = 20_000
}

/** How a walk ended. */
data class WalkResult(val visited: Int, val truncated: Boolean)

/**
 * Pre-order walk (same order as the recursive version it replaces) with an explicit stack, so
 * no tree depth can overflow the call stack. Children beyond [maxDepth], and nodes beyond
 * [maxNodes], are skipped and reported through [WalkResult.truncated]. [visit] returns true
 * to stop early.
 */
fun <N : Any> walkTree(
    roots: List<N>,
    childCount: (N) -> Int,
    childAt: (N, Int) -> N?,
    maxDepth: Int = TreeLimits.MAX_DEPTH,
    maxNodes: Int = TreeLimits.MAX_NODES,
    visit: (N) -> Boolean,
): WalkResult {
    class Frame(val node: N, val depth: Int)

    val stack = ArrayDeque<Frame>()
    var truncated = false
    // Never more than the node budget on the stack: a node with a million children cannot blow memory.
    fun room(visited: Int) = maxNodes - visited - stack.size
    for (root in roots.asReversed()) {
        if (room(0) > 0) stack.addLast(Frame(root, 1)) else truncated = true
    }
    var visited = 0
    while (stack.isNotEmpty()) {
        val frame = stack.removeLast()
        visited++
        if (visit(frame.node)) return WalkResult(visited, truncated)
        val count = childCount(frame.node)
        if (count <= 0) continue
        if (frame.depth >= maxDepth) {
            truncated = true
            continue
        }
        val take = minOf(count, room(visited).coerceAtLeast(0))
        if (take < count) truncated = true
        for (i in take - 1 downTo 0) childAt(frame.node, i)?.let { stack.addLast(Frame(it, frame.depth + 1)) }
    }
    return WalkResult(visited, truncated)
}
