import os
import base64
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException


# =====================
# Brevo Configuration
# =====================
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] =  os.getenv("BREVO_API_KEY")

api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
    sib_api_v3_sdk.ApiClient(configuration)
)

EMAIL_ID = os.getenv("EMAIL_ID")
SENDER = {
    "name": "Sidhilynx",
    "email": EMAIL_ID
}


class EmailSendError(Exception):
    pass


# =====================
# OTP EMAIL
# =====================
def send_password_reset_otp(email: str, otp: str):
    print("Function called")
    subject = "Reset your SidhiLynx account password"

    html_content = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#0a0a0a;color:#e5e7eb;font-family:Arial,sans-serif;">
  <table width="100%" style="padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" style="background:#111;border-radius:14px;padding:36px;">
          
          <tr>
            <td style="text-align:center;">
              <h2 style="color:#fff;margin-bottom:12px;">Password Reset</h2>
              <p style="font-size:14px;color:#cbd5f5;">
                Use the OTP below to reset your password.
              </p>
            </td>
          </tr>

          <tr>
            <td style="text-align:center;padding:28px 0;">
              <div style="
                font-size:28px;
                letter-spacing:6px;
                font-weight:600;
                background:#000;
                padding:14px 24px;
                border-radius:10px;
                display:inline-block;
                color:#fff;">
                {otp}
              </div>
            </td>
          </tr>

          <tr>
            <td style="font-size:13px;color:#9ca3af;text-align:center;">
              This OTP is valid for <b>10 minutes</b>.<br/>
              If you did not request this, please ignore this email.
            </td>
          </tr>

          <tr>
            <td style="padding-top:28px;font-size:11px;color:#6b7280;text-align:center;">
              © Sidhi • Security Notification
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        html_content=html_content,
        sender=SENDER,
        subject=subject
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
        print("Email sent nanba !")
    except ApiException as e:
        raise EmailSendError(str(e))
