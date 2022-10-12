using System;
using System.Security.Cryptography;
using System.Text;
using AtHackers.Abstractions;
using AtHackers.Exceptions;

namespace AtHackers.Hashers
{
    public class SHA256HASHER : BaseHasher
    {
        #region GenerateFinalHashSHA256 
        public override string GenerateHash(string Password, bool OnlyHashRequired = false)
        {
           if(string.IsNullOrEmpty(Password)) throw new ValueCannotBeNullException();
            return SecureHash(Password, OnlyHashRequired);
        }
        #endregion GenerateFinalHashSHA256


        #region GenerateHashForValidationSHA256
        private string GenerateHashForValidation(string passwordText, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var textToHash = passwordText + salt;
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(textToHash));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
        #endregion GenerateHashForValidationSHA256

        #region  ValidatePassword
        public override bool ValidatePassword(string plainInput,string HashedPassword)
        {
            if (!HashedPassword.Contains("@")) throw new InvalidSaltException();
            var normalPasswordAndSalt = RemovePeppers(HashedPassword);
            var hashedPasswordAndSalt = normalPasswordAndSalt.Split('@');
            if (hashedPasswordAndSalt == null || hashedPasswordAndSalt.Length != 2)
            {
                return false;
            }
            var salt = hashedPasswordAndSalt[0];
            if (salt == null)
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
        #region GenerateHashWithSalt
        private string HashPasswordTextWithSalt(string passwordText, out string salt, bool OnlyHashNeeded = false)
        {
            using (var sha256 = SHA256.Create())
            {
                if (OnlyHashNeeded == true)
                {
                    salt = "";
                    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(passwordText));
                    return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                }
                else
                {
                    salt = GenerateSalt();
                    var textToHash = passwordText + salt;
                    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(textToHash));
                    return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                }


            }
        }
        #endregion GenerateHashWithSalt

        #region SecureHashSHA256
        private string SecureHash(string PasswordToHash, bool OnlyHashRequired = false)
        {
            var hashWithSalt = "";
            string salt;
            var hashText = HashPasswordTextWithSalt(PasswordToHash, out salt, OnlyHashRequired);
            if (string.IsNullOrEmpty(salt)) return hashText;
            hashWithSalt = salt + "@" + hashText;
            hashWithSalt = "$" + hashWithSalt + "&";
            return hashWithSalt;
        }
        #endregion SecureHashSHA256
    }
}