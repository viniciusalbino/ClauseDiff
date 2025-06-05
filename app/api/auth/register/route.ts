import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

// Validation schema for registration
const registerSchema = z.object({
  firstName: z.string().min(1, "Nome é obrigatório").max(50, "Nome muito longo"),
  lastName: z.string().min(1, "Sobrenome é obrigatório").max(50, "Sobrenome muito longo"),
  email: z.string().email("Email inválido").toLowerCase(),
  password: z.string().min(6, "Senha deve ter pelo menos 6 caracteres").max(100, "Senha muito longa"),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    // Validate input data
    const validatedData = registerSchema.parse(body);
    
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: validatedData.email }
    });
    
    if (existingUser) {
      return NextResponse.json(
        { 
          message: "Um usuário com este email já existe",
          code: "USER_EXISTS" 
        },
        { status: 400 }
      );
    }
    
    // Hash password with salt
    const saltRounds = 12; // Higher than default for better security
    const hashedPassword = await bcrypt.hash(validatedData.password, saltRounds);
    
    // Create user
    const user = await prisma.user.create({
      data: {
        firstName: validatedData.firstName,
        lastName: validatedData.lastName,
        name: `${validatedData.firstName} ${validatedData.lastName}`.trim(),
        email: validatedData.email,
        password: hashedPassword,
        role: "USER", // Default role
        // emailVerified will be null until verified
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
        // Don't return password or other sensitive fields
      }
    });
    
    return NextResponse.json(
      {
        message: "Conta criada com sucesso",
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          name: user.name,
          email: user.email,
          role: user.role,
        }
      },
      { status: 201 }
    );
    
  } catch (error) {
    console.error("Registration error:", error);
    
    if (error instanceof z.ZodError) {
      // Return validation errors
      return NextResponse.json(
        {
          message: "Dados inválidos",
          errors: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message
          }))
        },
        { status: 400 }
      );
    }
    
    // Check for database constraint errors
    if (error instanceof Error && error.message.includes('Unique constraint')) {
      return NextResponse.json(
        { 
          message: "Um usuário com este email já existe",
          code: "USER_EXISTS" 
        },
        { status: 400 }
      );
    }
    
    // Generic server error
    return NextResponse.json(
      { 
        message: "Erro interno do servidor. Tente novamente.",
        code: "INTERNAL_ERROR" 
      },
      { status: 500 }
    );
  }
} 