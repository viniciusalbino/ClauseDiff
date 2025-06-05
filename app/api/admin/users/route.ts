/**
 * Admin API Route: User Management
 * 
 * This route demonstrates RBAC implementation with admin-only access
 * for user management operations.
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "../../../../src/lib/prisma";
import { requireAuthAndRole, ROLES } from "../../../../src/lib/permissions";
import { z } from "zod";

// Request validation schemas
const updateUserSchema = z.object({
  id: z.string().uuid(),
  role: z.enum(['USER', 'ADMIN']).optional(),
  firstName: z.string().min(1).optional(),
  lastName: z.string().min(1).optional(),
  city: z.string().optional(),
  state: z.string().optional(),
});

/**
 * GET /api/admin/users
 * Get all users (admin only)
 */
export async function GET(request: NextRequest) {
  // Check authentication and admin role
  const authError = await requireAuthAndRole(ROLES.ADMIN);
  if (authError) return authError;

  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    const search = searchParams.get('search') || '';
    const role = searchParams.get('role') || undefined;

    const skip = (page - 1) * limit;

    // Build where clause for filtering
    const where: any = {};
    
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
      ];
    }
    
    if (role && (role === 'USER' || role === 'ADMIN')) {
      where.role = role;
    }

    // Get users with pagination
    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          city: true,
          state: true,
          role: true,
          createdAt: true,
          emailVerified: true,
          _count: {
            select: {
              auditLogs: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
        skip,
        take: limit,
      }),
      prisma.user.count({ where }),
    ]);

    return NextResponse.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    return NextResponse.json(
      { error: 'Failed to fetch users' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/admin/users
 * Update user information (admin only)
 */
export async function PUT(request: NextRequest) {
  // Check authentication and admin role
  const authError = await requireAuthAndRole(ROLES.ADMIN);
  if (authError) return authError;

  try {
    const body = await request.json();
    const validatedData = updateUserSchema.parse(body);

    const { id, ...updateData } = validatedData;

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: { id: true, email: true, role: true },
    });

    if (!existingUser) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    // Update user
    const updatedUser = await prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        city: true,
        state: true,
        role: true,
        updatedAt: true,
      },
    });

    // Log the admin action
    await prisma.auditLog.create({
      data: {
        eventType: 'USER_UPDATED_BY_ADMIN',
        details: {
          targetUserId: id,
          targetUserEmail: existingUser.email,
          changes: updateData,
          previousRole: existingUser.role,
        },
      },
    });

    return NextResponse.json({
      message: 'User updated successfully',
      user: updatedUser,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error updating user:', error);
    return NextResponse.json(
      { error: 'Failed to update user' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/admin/users/[id]
 * Delete user (admin only)
 */
export async function DELETE(request: NextRequest) {
  // Check authentication and admin role
  const authError = await requireAuthAndRole(ROLES.ADMIN);
  if (authError) return authError;

  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('id');

    if (!userId) {
      return NextResponse.json(
        { error: 'User ID is required' },
        { status: 400 }
      );
    }

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!existingUser) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    // Prevent admin from deleting themselves
    // Note: We'd need to get the current user's ID to implement this properly
    // For now, this is a basic implementation

    // Delete user (cascade will handle related records)
    await prisma.user.delete({
      where: { id: userId },
    });

    // Log the admin action
    await prisma.auditLog.create({
      data: {
        eventType: 'USER_DELETED_BY_ADMIN',
        details: {
          deletedUserId: userId,
          deletedUserEmail: existingUser.email,
          deletedUserRole: existingUser.role,
        },
      },
    });

    return NextResponse.json({
      message: 'User deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    return NextResponse.json(
      { error: 'Failed to delete user' },
      { status: 500 }
    );
  }
} 