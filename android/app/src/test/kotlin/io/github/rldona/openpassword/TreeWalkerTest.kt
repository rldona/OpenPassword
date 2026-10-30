package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.TreeLimits
import io.github.rldona.openpassword.autofill.walkTree
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** ID-INT-18: hostile trees finish, without recursion. */
class TreeWalkerTest {
    private class Node(val id: Int, val children: List<Node> = emptyList())

    private fun walk(roots: List<Node>, maxDepth: Int = TreeLimits.MAX_DEPTH, maxNodes: Int = TreeLimits.MAX_NODES, order: MutableList<Int>? = null) =
        walkTree(roots, { it.children.size }, { n, i -> n.children[i] }, maxDepth, maxNodes) { order?.add(it.id); false }

    @Test
    fun `visits in pre-order like the recursive walk`() {
        val tree = Node(1, listOf(Node(2, listOf(Node(3), Node(4))), Node(5)))
        val order = mutableListOf<Int>()
        val result = walk(listOf(tree, Node(6)), order = order)
        assertEquals(listOf(1, 2, 3, 4, 5, 6), order)
        assertFalse(result.truncated)
    }

    @Test
    fun `a very deep tree ends without StackOverflowError and is cut at the depth limit`() {
        var node = Node(0)
        repeat(1_000_000) { node = Node(it + 1, listOf(node)) } // built bottom-up, no recursion
        val result = walk(listOf(node))
        assertEquals(TreeLimits.MAX_DEPTH, result.visited)
        assertTrue(result.truncated)
    }

    @Test
    fun `a very wide tree is cut at the node limit and keeps the stack bounded`() {
        val wide = Node(0, List(2_000_000) { Node(it + 1) })
        val result = walk(listOf(wide))
        assertEquals(TreeLimits.MAX_NODES, result.visited)
        assertTrue(result.truncated)
    }

    @Test
    fun `a normal screen is not truncated`() {
        val screen = Node(0, List(300) { Node(it + 1, List(5) { c -> Node(1000 + c) }) })
        val result = walk(listOf(screen))
        assertEquals(1 + 300 + 1500, result.visited)
        assertFalse(result.truncated)
    }

    @Test
    fun `stops early when visit returns true`() {
        val tree = Node(1, listOf(Node(2), Node(3), Node(4)))
        val seen = mutableListOf<Int>()
        val result = walkTree(listOf(tree), { it.children.size }, { n, i -> n.children[i] }) { seen += it.id; it.id == 3 }
        assertEquals(listOf(1, 2, 3), seen)
        assertEquals(3, result.visited)
    }

    @Test
    fun `limits apply to explicit small values`() {
        val tree = Node(1, listOf(Node(2, listOf(Node(3)))))
        assertEquals(2, walk(listOf(tree), maxDepth = 2).visited)
        assertEquals(1, walk(listOf(tree), maxNodes = 1).visited)
    }
}
