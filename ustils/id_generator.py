import uuid
def generate_user_id() -> str:
    return f"SIDHI_{uuid.uuid4().hex[:12].upper()}"


def generate_invoice_id() -> str:
    return f"INV_{uuid.uuid4().hex[:12].upper()}"

def generate_job_id() -> str:
    return f"JOB_{uuid.uuid4().hex[:12].upper()}"
