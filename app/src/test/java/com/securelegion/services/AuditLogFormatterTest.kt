package com.securelegion.services

import org.junit.Assert.assertEquals
import org.junit.Test

class AuditLogFormatterTest {

    @Test
    fun describe_coversAllKnownOpTypes() {
        assertEquals("Alice created the group",
            AuditLogFormatter.describe("GroupCreate", "Alice"))
        assertEquals("Alice invited a member",
            AuditLogFormatter.describe("MemberInvite", "Alice"))
        assertEquals("Bob joined the group",
            AuditLogFormatter.describe("MemberAccept", "Bob"))
        assertEquals("Alice removed a member",
            AuditLogFormatter.describe("MemberRemove", "Alice"))
        assertEquals("Alice unbanned a member",
            AuditLogFormatter.describe("MemberUnban", "Alice"))
        assertEquals("Alice updated admin rights",
            AuditLogFormatter.describe("RoleSet", "Alice"))
        assertEquals("Alice updated group settings",
            AuditLogFormatter.describe("MetadataSet", "Alice"))
        assertEquals("Alice deleted the group",
            AuditLogFormatter.describe("GroupDelete", "Alice"))
    }

    @Test
    fun describe_unknownOpFallsBackToNameAndType() {
        assertEquals("Alice • MsgAdd",
            AuditLogFormatter.describe("MsgAdd", "Alice"))
    }
}
