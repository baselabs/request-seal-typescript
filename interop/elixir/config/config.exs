import Config
expected_otp = "29"
running_otp = to_string(:erlang.system_info(:otp_release))
if running_otp != expected_otp do
  raise "Reciprocal interop requires Erlang/OTP #{expected_otp}; running #{running_otp}."
end
