using System;
using System.Security.Cryptography;
using System.Text;
using AtHackers.Abstractions;
using AtHackers.Exceptions;

namespace AtHackers.Hashers
{
    public class SHA512HASHER : BaseHasher
    {
        #region GenerateFinalHashSHA512
        public override string GenerateHash(string Password, bool OnlyHashRequired = false)
        {
            if(string.IsNullOrEmpty(Password)) throw new ValueCannotBeNullException();
            return SecureHash(Password, OnlyHashRequired);
        }
        #endregion GenerateFinalHashSHA512


        #region GenerateHashForValidationSHA512
        private string GenerateHashForValidation(string passwordText, string salt)
        {
            using (var sha256 = SHA512.Create())
            {
                var textToHash = passwordText + salt;
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(textToHash));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
        #endregion GenerateHashForValidationSHA512

        #region  ValidatePassword
        public override bool ValidatePassword(string plainInput,string HashedPassword)
        {
            if(string.IsNullOrEmpty(plainInput) || string.IsNullOrEmpty(plainInput)) throw new ValueCannotBeNullException();
            if (!HashedPassword.Contains("@")) throw new InvalidSaltException();
            var normalPasswordAndSalt = RemovePeppers(HashedPassword);
            var hashedPasswordAndSalt = normalPasswordAndSalt.Split('@');
            if (hashedPasswordAndSalt == null || hashedPasswordAndSalt.Length != 2)
            {
                return false;
            }
            var salt = hashedPasswordAndSalt[0];
            if (string.IsNullOrEmpty(salt) && salt != "$")
            {
                throw new ArgumentException("Cannot Accept A Null Value For The Required Parameter: Salt");
            }
            var hashOfPasswordToCheck = GenerateHashForValidation(plainInput, salt);
            if (String.Compare(hashedPasswordAndSalt[1], hashOfPasswordToCheck) == 0)
            {
                return true;
            }
            return false;
        }
        #endregion ValidatePassword



        #region HashPasswordTextWithSaltSHA512

        protected string HashPasswordTextWithSalt(string passwordText, out string salt, bool OnlyHashNeeded = false)
        {
            using (var sha512 = SHA512.Create())
            {
                if (OnlyHashNeeded == true)
                {
                    salt = "";
                    var hashedBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(passwordText));
                    return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                }
                else
                {
                    salt = GenerateSalt();
                    var textToHash = passwordText + salt;
                    var hashedBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(textToHash));
                    return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                }

            }
        }
        #endregion HashPasswordTextWithSaltSHA512

        #region SecureHashSHA512
        private string SecureHash(string PasswordToHash, bool OnlyHashRequired = false)
        {
            var hashWithSalt = "";
            string salt;
            var hashText = HashPasswordTextWithSalt(PasswordToHash, out salt, OnlyHashRequired);
            if(string.IsNullOrEmpty(salt)) return hashText;
            hashWithSalt = salt + "@" + hashText;
            hashWithSalt = "$" + hashWithSalt + "&";
            return hashWithSalt;
        }
        #endregion SecureHashSHA512
    }

}