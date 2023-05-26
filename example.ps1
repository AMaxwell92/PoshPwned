import-module '.\PoshPwned.psm1'

Test-PasswordPwned -Password ( 'Password!123' | ConvertTo-SecureString -AsPlainText -Force )
