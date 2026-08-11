resource "aws_verifiedpermissions_policy_store" "aegisai" {
  description = var.policy_store_description

  validation_settings {
    mode = var.policy_store_validation_mode
  }
}

resource "aws_verifiedpermissions_schema" "aegisai" {
  policy_store_id = aws_verifiedpermissions_policy_store.aegisai.policy_store_id

  definition {
    value = file("${path.module}/../../policies/cedar/identity/schema.json")
  }
}

resource "aws_verifiedpermissions_policy" "finance_kb_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.aegisai.policy_store_id

  definition {
    static {
      statement = file(
        "${path.module}/../../policies/cedar/identity/finance-kb-read.cedar"
      )
    }
  }

  depends_on = [
    aws_verifiedpermissions_schema.aegisai
  ]
}

resource "aws_verifiedpermissions_policy" "model_invoke" {
  policy_store_id = aws_verifiedpermissions_policy_store.aegisai.policy_store_id

  definition {
    static {
      statement = file(
        "${path.module}/../../policies/cedar/identity/model-invoke.cedar"
      )
    }
  }

  depends_on = [
    aws_verifiedpermissions_schema.aegisai
  ]
}

resource "aws_verifiedpermissions_policy" "tool_invoke" {
  policy_store_id = aws_verifiedpermissions_policy_store.aegisai.policy_store_id

  definition {
    static {
      statement = file(
        "${path.module}/../../policies/cedar/identity/tool-invoke.cedar"
      )
    }
  }

  depends_on = [
    aws_verifiedpermissions_schema.aegisai
  ]
}

resource "aws_verifiedpermissions_policy" "production_intern_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.aegisai.policy_store_id

  definition {
    static {
      statement = file(
        "${path.module}/../../policies/cedar/identity/production-intern-deny.cedar"
      )
    }
  }

  depends_on = [
    aws_verifiedpermissions_schema.aegisai
  ]
}
