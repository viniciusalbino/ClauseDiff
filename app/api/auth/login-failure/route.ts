import { NextRequest, NextResponse } from 'next/server';

// This endpoint is called from NextAuth callbacks to record login failures
// It helps coordinate with the middleware's progressive backoff system
export async function POST(request: NextRequest) {
  try {
    const { ip, type = 'failure' } = await request.json();
    
    if (!ip) {
      return NextResponse.json(
        { error: 'IP address is required' },
        { status: 400 }
      );
    }
    
    // Get client IP if not provided
    const clientIp = ip || request.ip || request.headers.get('x-forwarded-for') || 'unknown';
    
    if (type === 'failure') {
      // Import the middleware function (this creates a coupling, but necessary for coordination)
      // In production, this should use a shared service/store
      const { recordLoginFailure } = await import('../../../../middleware');
      
      // This will trigger progressive backoff if appropriate
      recordLoginFailure(clientIp);
      
      return NextResponse.json({ 
        success: true, 
        message: 'Login failure recorded' 
      });
    }
    
    return NextResponse.json({ 
      success: true, 
      message: 'No action taken' 
    });
    
  } catch (error) {
    console.error('Error in login-failure endpoint:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 