from pydantic import BaseModel, Field


class TOTPSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code: str


class TOTPEnableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPVerifyRequest(BaseModel):
    login_token: str
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPDisableRequest(BaseModel):
    password: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
