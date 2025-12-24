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
          sdk.Query.equal('$id', user.$id)
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
  <title>FitSphere – Password Reset</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #2c2c2c;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
        Roboto, Helvetica, Arial, sans-serif;
      color: #9ecf98;
    }

    .wrapper {
      max-width: 600px;
      margin: 40px auto;
      padding: 20px;
    }

    .container {
      background-color: #1f1f1f;
      border-radius: 18px;
      padding: 36px 32px;
      border: 1px solid rgba(158, 207, 152, 0.25);
    }

    .brand {
      text-align: center;
      margin-bottom: 28px;
    }

    .brand h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 600;
      letter-spacing: 1px;
      color: #9ecf98;
    }

    h2 {
      margin: 0 0 14px;
      font-size: 22px;
      font-weight: 600;
      color: #ffffff;
    }

    p {
      font-size: 15px;
      line-height: 1.7;
      color: #d0d0d0;
      margin: 0 0 16px;
    }

    .otp-code {
      background-color: #9ecf98;
      color: #1f1f1f;
      font-size: 34px;
      font-weight: 700;
      text-align: center;
      padding: 22px 0;
      border-radius: 14px;
      letter-spacing: 10px;
      margin: 32px 0;
    }

    .expiry {
      text-align: center;
      font-size: 14px;
      color: #bdbdbd;
      margin-bottom: 28px;
    }

    .notice {
      border-top: 1px solid rgba(158, 207, 152, 0.25);
      padding-top: 16px;
      font-size: 14px;
      color: #bdbdbd;
      margin-top: 24px;
    }

    .footer {
      margin-top: 36px;
      font-size: 13px;
      color: #9a9a9a;
      text-align: center;
    }
  </style>
</head>

<body>
  <div class="wrapper">
    <div class="container">

      <div class="brand">
        <h1>FitSphere</h1>
      </div>

      <h2>Password reset</h2>

      <p>
        We received a request to reset the password for your FitSphere account.
        Use the one-time code below to continue.
      </p>

      <div class="otp-code">${otp}</div>

      <div class="expiry">
        This code expires in <strong>${OTP_EXPIRY_MINUTES} minutes</strong>.
      </div>

      <div class="notice">
        If you didn’t request this password reset, no action is required.
        Your account will remain secure.
      </div>

      <div class="footer">
        © FitSphere · Train smarter. Live stronger.
      </div>

    </div>
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
