import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../src/lib/auth-config';
import { prisma } from '../../../../src/lib/prisma';
import { z } from 'zod';

// Validation schema for profile update
const updateProfileSchema = z.object({
  firstName: z.string().min(1, 'Nome é obrigatório').max(50, 'Nome deve ter no máximo 50 caracteres'),
  lastName: z.string().min(1, 'Sobrenome é obrigatório').max(50, 'Sobrenome deve ter no máximo 50 caracteres'),
  city: z.string().max(100, 'Cidade deve ter no máximo 100 caracteres').optional().or(z.literal('')),
  state: z.string().max(50, 'Estado deve ter no máximo 50 caracteres').optional().or(z.literal('')),
  cpf: z.string()
    .optional()
    .or(z.literal(''))
    .refine((val) => {
      if (!val) return true; // CPF is optional
      // Remove non-numeric characters
      const digits = val.replace(/\D/g, '');
      return digits.length === 11;
    }, 'CPF deve ter 11 dígitos'),
});

// GET - Fetch user profile
export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Não autorizado' },
        { status: 401 }
      );
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        city: true,
        state: true,
        cpf: true,
        role: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!user) {
      return NextResponse.json(
        { error: 'Usuário não encontrado' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      user
    });

  } catch (error) {
    console.error('Error fetching user profile:', error);
    return NextResponse.json(
      { error: 'Erro interno do servidor' },
      { status: 500 }
    );
  }
}

// PUT - Update user profile
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Não autorizado' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const validatedData = updateProfileSchema.parse(body);

    // Clean CPF (remove formatting)
    const cleanCpf = validatedData.cpf ? validatedData.cpf.replace(/\D/g, '') : null;

    // Check if CPF is already in use by another user
    if (cleanCpf) {
      const existingUser = await prisma.user.findFirst({
        where: {
          cpf: cleanCpf,
          email: { not: session.user.email }
        }
      });

      if (existingUser) {
        return NextResponse.json(
          { error: 'CPF já está em uso por outro usuário' },
          { status: 400 }
        );
      }
    }

    // Update user profile
    const updatedUser = await prisma.user.update({
      where: { email: session.user.email },
      data: {
        firstName: validatedData.firstName,
        lastName: validatedData.lastName,
        city: validatedData.city || null,
        state: validatedData.state || null,
        cpf: cleanCpf,
        updatedAt: new Date()
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        city: true,
        state: true,
        cpf: true,
        role: true,
        createdAt: true,
        updatedAt: true
      }
    });

    // Log the profile update event
    await prisma.auditLog.create({
      data: {
        userId: updatedUser.id,
        eventType: 'PROFILE_UPDATE',
        ip: request.ip || request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent'),
        details: {
          updatedFields: Object.keys(validatedData),
          timestamp: new Date().toISOString(),
        }
      }
    });

    return NextResponse.json({
      success: true,
      message: 'Perfil atualizado com sucesso',
      user: updatedUser
    });

  } catch (error) {
    console.error('Error updating user profile:', error);
    
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { 
          error: 'Dados inválidos',
          details: error.errors[0]?.message || 'Dados de entrada inválidos',
          field: error.errors[0]?.path[0] || 'unknown'
        },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: 'Erro interno do servidor' },
      { status: 500 }
    );
  }
}

// DELETE - Delete user account (soft delete or hard delete)
export async function DELETE(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Não autorizado' },
        { status: 401 }
      );
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email }
    });

    if (!user) {
      return NextResponse.json(
        { error: 'Usuário não encontrado' },
        { status: 404 }
      );
    }

    // Log the account deletion event before deleting
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        eventType: 'ACCOUNT_DELETE',
        ip: request.ip || request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent'),
        details: {
          email: user.email,
          timestamp: new Date().toISOString(),
        }
      }
    });

    // For LGPD/GDPR compliance, we should offer both soft delete and hard delete
    // For now, implementing hard delete (as per user request)
    await prisma.user.delete({
      where: { email: session.user.email }
    });

    return NextResponse.json({
      success: true,
      message: 'Conta excluída com sucesso'
    });

  } catch (error) {
    console.error('Error deleting user account:', error);
    return NextResponse.json(
      { error: 'Erro interno do servidor' },
      { status: 500 }
    );
  }
} 