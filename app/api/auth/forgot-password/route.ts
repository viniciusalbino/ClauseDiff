import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '../../../../src/lib/prisma';
import { z } from 'zod';
import crypto from 'crypto';

// Validation schema for forgot password request
const forgotPasswordSchema = z.object({
  email: z.string().email('Email inválido').toLowerCase(),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email } = forgotPasswordSchema.parse(body);

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { email }
    });

    // Always return success to prevent email enumeration
    // But only send email if user actually exists
    if (user) {
      // Generate secure reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      // Save reset token to database
      await prisma.user.update({
        where: { email },
        data: {
          resetToken,
          resetTokenExpiry,
        }
      });

      // In production, send actual email
      // For development, log the reset link
      const resetUrl = `${process.env.NEXTAUTH_URL}/reset-password?token=${resetToken}`;
      
      console.log(`[PASSWORD RESET] Reset link for ${email}: ${resetUrl}`);
      
      // TODO: Send actual email in production
      // await sendPasswordResetEmail(email, resetUrl);
    }

    // Always return success response (security best practice)
    return NextResponse.json({
      success: true,
      message: 'Se o email estiver cadastrado, você receberá um link de recuperação de senha.',
    });

  } catch (error) {
    console.error('Error in forgot-password endpoint:', error);
    
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { 
          error: 'Dados inválidos',
          details: error.errors[0]?.message || 'Email é obrigatório'
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

// TODO: In production, implement actual email sending with your email service (SendGrid, Amazon SES, etc.) 