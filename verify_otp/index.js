/**
 * Appwrite Function: Verify OTP and Reset Password (TOTP-based)
 *
 * This function verifies the TOTP using the user's secret and resets the password.
 * No database OTP storage needed - validation is done using the secret.
 *
 * Runtime: Node.js 18+
 *
 * Environment Variables Required:
 * - APPWRITE_FUNCTION_PROJECT_ID
 * - APPWRITE_API_KEY (with appropriate permissions)
 * - DATABASE_ID
 * - USERS_COLLECTION_ID
 */
const sdk = require("node-appwrite");
const { authenticator } = require("otplib");
// TOTP Configuration - MUST match the send function
const OTP_EXPIRY_MINUTES = 10;
const OTP_STEP_SECONDS = OTP_EXPIRY_MINUTES * 60;
// Configure otplib
authenticator.options = {
  digits: 6,
  step: OTP_STEP_SECONDS,
  window: 0, // Strict validation - no backward/forward window
};
/**
 * Main function handler
 */
module.exports = async ({ req, res, log, error }) => {
  try {
    // Parse request body
    const payload = JSON.parse(req.body || "{}");
    const { email, otp, newPassword } = payload;
    // Validate input
    if (!email || !otp || !newPassword) {
      return res.json(
        {
          success: false,
          message: "Email, OTP, and new password are required",
        },
        400
      );
    }
    // Validate OTP format (6 digits)
    if (!/^\d{6}$/.test(otp)) {
      return res.json(
        {
          success: false,
          message: "Invalid OTP format. OTP must be 6 digits.",
        },
        400
      );
    }
    // Validate password strength
    if (newPassword.length < 8) {
      return res.json(
        {
          success: false,
          message: "Password must be at least 8 characters long",
        },
        400
      );
    }
    // Initialize Appwrite client
    const client = new sdk.Client()
      .setEndpoint(
        process.env.APPWRITE_ENDPOINT || "https://cloud.appwrite.io/v1"
      )
      .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
      .setKey(process.env.APPWRITE_API_KEY);
    const database = new sdk.Databases(client);
    const users = new sdk.Users(client);
    // Find user by email
    let user = null;
    let userDocument = null;

    try {
      const usersList = await users.list([sdk.Query.equal("email", [email])]);
      if (usersList.total === 0) {
        return res.json(
          {
            success: false,
            message: "No account found with this email address",
          },
          404
        );
      }
      user = usersList.users[0];
    } catch (err) {
      error("Error finding user:", err);
      return res.json(
        {
          success: false,
          message: "Error verifying email address",
        },
        500
      );
    }
    // Get user document to retrieve secret
    try {
      const userDocs = await database.listDocuments(
        process.env.DATABASE_ID,
        process.env.USERS_COLLECTION_ID,
        [sdk.Query.equal("$id", user.$id)]
      );

      if (userDocs.total === 0) {
        return res.json(
          {
            success: false,
            message: "User profile not found",
          },
          404
        );
      }
      userDocument = userDocs.documents[0];
    } catch (err) {
      error("Error fetching user document:", err);
      return res.json(
        {
          success: false,
          message: "Error accessing user profile",
        },
        500
      );
    }
    // Check if user has a password reset secret
    const secret = userDocument.passwordResetSecret;

    if (!secret) {
      return res.json(
        {
          success: false,
          message: "No OTP request found. Please request a new OTP.",
        },
        400
      );
    }
    // Verify the TOTP
    let isValid = false;
    try {
      isValid = authenticator.verify({
        token: otp,
        secret: secret,
      });
    } catch (err) {
      error("Error verifying TOTP:", err);
      return res.json(
        {
          success: false,
          message: "Invalid OTP or OTP has expired",
        },
        400
      );
    }
    if (!isValid) {
      return res.json(
        {
          success: false,
          message: "Invalid OTP or OTP has expired. Please request a new OTP.",
        },
        400
      );
    }
    log(`OTP verified successfully for user ${user.$id}`);
    // Update the user's password
    try {
      await users.updatePassword(user.$id, newPassword);
      log(`Password updated successfully for user ${user.$id}`);
    } catch (err) {
      error("Error updating password:", err);
      return res.json(
        {
          success: false,
          message: "Failed to update password. Please try again.",
        },
        500
      );
    }
    // Remove the password reset secret to prevent reuse
    try {
      await database.updateDocument(
        process.env.DATABASE_ID,
        process.env.USERS_COLLECTION_ID,
        userDocument.$id,
        { passwordResetSecret: null }
      );
      log(`Password reset secret removed for user ${user.$id}`);
    } catch (err) {
      // Non-critical error - password was already updated
      log(
        "Note: Could not regenerate secret, but password was updated:",
        err.message
      );
    }
    return res.json({
      success: true,
      message:
        "Password reset successful! You can now log in with your new password.",
    });
  } catch (err) {
    error("Unexpected error:", err);
    return res.json(
      {
        success: false,
        message: "An unexpected error occurred. Please try again.",
      },
      500
    );
  }
};
