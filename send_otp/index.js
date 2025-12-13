/**
 * Appwrite Function: Send Password Reset OTP (TOTP-based)
 * 
 * This function generates a TOTP using the user's secret and sends it via email.
 * No database storage needed - OTP is validated using the same secret.
 * 
 * Runtime: Node.js 18+
 * 
 * Environment Variables Required:
 * - APPWRITE_FUNCTION_PROJECT_ID
 * - APPWRITE_API_KEY (with appropriate permissions)
 * - DATABASE_ID
 * - USERS_COLLECTION_ID
 * - SMTP_HOST
 * - SMTP_PORT
 * - SMTP_USER
 * - SMTP_PASSWORD
 * - SMTP_FROM_EMAIL
 */
const sdk = require('node-appwrite');
const nodemailer = require('nodemailer');
const { authenticator } = require('otplib');
// TOTP Configuration
const OTP_EXPIRY_MINUTES = 10;
const OTP_STEP_SECONDS = OTP_EXPIRY_MINUTES * 60; // 600 seconds = 10 minutes
// Configure otplib
authenticator.options = {
  digits: 6,
  step: OTP_STEP_SECONDS, // OTP valid for 10 minutes
  window: 0, // No backward/forward window (strict time validation)
};
/**
 * Generate a random secret for TOTP
 */
function generateSecret() {
  return authenticator.generateSecret();
}
/**
 * Main function handler
 */
module.exports = async ({ req, res, log, error }) => {
  try {
    // Parse request body
    const payload = JSON.parse(req.body || '{}');
    const { email } = payload;
    // Validate input
    if (!email) {
      return res.json({
        success: false,
        message: 'Email is required',
      }, 400);
    }
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.json({
        success: false,
        message: 'Invalid email format',
      }, 400);
    }
    // Initialize Appwrite client
    const client = new sdk.Client()
      .setEndpoint(process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1')
      .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
      .setKey(process.env.APPWRITE_API_KEY);
    const database = new sdk.Databases(client);
    const users = new sdk.Users(client);
    // Find user by email
    let user = null;
    let userDocument = null;
    
    try {
      const usersList = await users.list([
        sdk.Query.equal('email', [email])
      ]);
      if (usersList.total === 0) {
        return res.json({
          success: false,
          message: 'No account found with this email address',
        }, 404);
      }
      user = usersList.users[0];
    } catch (err) {
      error('Error finding user:', err);
      return res.json({
        success: false,
        message: 'Error verifying email address',
      }, 500);
    }
    // Get user document from database to retrieve/update secret
    try {
      const userDocs = await database.listDocuments(
        process.env.DATABASE_ID,
        process.env.USERS_COLLECTION_ID,
        [
          sdk.Query.equal('uid', [user.$id])
        ]
      );
      if (userDocs.total === 0) {
        return res.json({
          success: false,
          message: 'User profile not found',
        }, 404);
      }
      userDocument = userDocs.documents[0];
    } catch (err) {
      error('Error fetching user document:', err);
      return res.json({
        success: false,
        message: 'Error accessing user profile',
      }, 500);
    }
    // Generate or get existing secret
    let secret = userDocument.passwordResetSecret;
    
    if (!secret) {
      // Generate a new secret if user doesn't have one
      secret = generateSecret();
      
      try {
        await database.updateDocument(
          process.env.DATABASE_ID,
          process.env.USERS_COLLECTION_ID,
          userDocument.$id,
          {
            passwordResetSecret: secret,
          }
        );
        log(`Generated new password reset secret for user ${user.$id}`);
      } catch (err) {
        error('Error updating user secret:', err);
        return res.json({
          success: false,
          message: 'Failed to generate OTP. Please try again.',
        }, 500);
      }
    }
    // Generate TOTP using the secret
    const otp = authenticator.generate(secret);
    log(`Generated TOTP for ${email}: ${otp}`);
    // Send email with OTP
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_PORT === '465',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      });
      const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {
              font-family: Arial, sans-serif;
              line-height: 1.6;
              color: #333;
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
            }
            .container {
              background-color: #f9f9f9;
              border-radius: 10px;
              padding: 30px;
            }
            .otp-code {
              background-color: #9ECF98;
              color: #2C2C2C;
              font-size: 32px;
              font-weight: bold;
              text-align: center;
              padding: 20px;
              border-radius: 8px;
              letter-spacing: 8px;
              margin: 20px 0;
            }
            .warning {
              background-color: #fff3cd;
              border-left: 4px solid #ffc107;
              padding: 12px;
              margin: 20px 0;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Password Reset Request</h2>
            <p>Hi there,</p>
            <p>We received a request to reset your password. Use the OTP code below to complete the process:</p>
            
            <div class="otp-code">${otp}</div>
            
            <p><strong>This code will expire in ${OTP_EXPIRY_MINUTES} minutes.</strong></p>
            
            <div class="warning">
              <strong>⚠️ Security Notice:</strong><br>
              If you didn't request this password reset, please ignore this email and your password will remain unchanged.
            </div>
            
            <p>Thanks,<br>Gym App Team</p>
          </div>
        </body>
        </html>
      `;
      await transporter.sendMail({
        from: process.env.SMTP_FROM_EMAIL,
        to: email,
        subject: `Your Password Reset Code: ${otp}`,
        html: emailHtml,
        text: `Your password reset OTP is: ${otp}\n\nThis code will expire in ${OTP_EXPIRY_MINUTES} minutes.\n\nIf you didn't request this, please ignore this email.`,
      });
      log(`OTP email sent successfully to ${email}`);
    } catch (err) {
      error('Error sending email:', err);
      return res.json({
        success: false,
        message: 'Failed to send OTP email. Please try again.',
      }, 500);
    }
    return res.json({
      success: true,
      message: `OTP sent to ${email}. Please check your inbox.`,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
    });
  } catch (err) {
    error('Unexpected error:', err);
    return res.json({
      success: false,
      message: 'An unexpected error occurred. Please try again.',
    }, 500);
  }
};
