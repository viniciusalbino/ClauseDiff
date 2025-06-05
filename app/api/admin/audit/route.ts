/**
 * Admin API Route: Audit Log Management
 * 
 * This route demonstrates RBAC implementation with permission-based access
 * for viewing audit logs and security events.
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../src/lib/prisma";
import { requireAuthAndPermission, PERMISSIONS } from "../../../../src/lib/permissions";

/**
 * GET /api/admin/audit
 * Get audit logs (requires AUDIT_LOG_READ permission)
 */
export async function GET(request: NextRequest) {
  // Check authentication and audit read permission
  const authError = await requireAuthAndPermission(PERMISSIONS.AUDIT_LOG_READ);
  if (authError) return authError;

  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');
    const eventType = searchParams.get('eventType') || undefined;
    const userId = searchParams.get('userId') || undefined;
    const startDate = searchParams.get('startDate') || undefined;
    const endDate = searchParams.get('endDate') || undefined;

    const skip = (page - 1) * limit;

    // Build where clause for filtering
    const where: any = {};
    
    if (eventType) {
      where.eventType = eventType;
    }
    
    if (userId) {
      where.userId = userId;
    }
    
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) {
        where.timestamp.gte = new Date(startDate);
      }
      if (endDate) {
        where.timestamp.lte = new Date(endDate);
      }
    }

    // Get audit logs with pagination
    const [auditLogs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              role: true,
            },
          },
        },
        orderBy: {
          timestamp: 'desc',
        },
        skip,
        take: limit,
      }),
      prisma.auditLog.count({ where }),
    ]);

    // Get summary statistics
    const eventTypeStats = await prisma.auditLog.groupBy({
      by: ['eventType'],
      _count: {
        id: true,
      },
      where: {
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        },
      },
    });

    return NextResponse.json({
      auditLogs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
      statistics: {
        eventTypes: eventTypeStats,
        totalLast24h: eventTypeStats.reduce((sum, stat) => sum + stat._count.id, 0),
      },
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    return NextResponse.json(
      { error: 'Failed to fetch audit logs' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/admin/audit
 * Delete old audit logs (requires AUDIT_LOG_READ permission)
 */
export async function DELETE(request: NextRequest) {
  // Check authentication and audit read permission
  const authError = await requireAuthAndPermission(PERMISSIONS.AUDIT_LOG_READ);
  if (authError) return authError;

  try {
    const { searchParams } = new URL(request.url);
    const olderThanDays = parseInt(searchParams.get('olderThanDays') || '90');

    if (olderThanDays < 30) {
      return NextResponse.json(
        { error: 'Cannot delete audit logs newer than 30 days' },
        { status: 400 }
      );
    }

    const cutoffDate = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

    // Delete old audit logs
    const result = await prisma.auditLog.deleteMany({
      where: {
        timestamp: {
          lt: cutoffDate,
        },
      },
    });

    // Log the cleanup action
    await prisma.auditLog.create({
      data: {
        eventType: 'AUDIT_LOG_CLEANUP',
        details: {
          deletedCount: result.count,
          cutoffDate: cutoffDate.toISOString(),
          olderThanDays,
        },
      },
    });

    return NextResponse.json({
      message: `Deleted ${result.count} audit log entries older than ${olderThanDays} days`,
      deletedCount: result.count,
    });
  } catch (error) {
    console.error('Error deleting audit logs:', error);
    return NextResponse.json(
      { error: 'Failed to delete audit logs' },
      { status: 500 }
    );
  }
} 