using System;
using System.Security.Cryptography;

namespace AtHackers.Abstractions
{
    public abstract class BaseHasher
    {
       public abstract  string GenerateHash(string Password, bool OnlyHashRequired = false);

        #region RemoveSpecialCharacters
        protected string RemovePeppers(string PepperedHash)
        {
            PepperedHash = PepperedHash.Replace(PepperedHash[0].ToString(), "");
            PepperedHash = PepperedHash.Replace(PepperedHash[PepperedHash.Length - 1].ToString(), "");
            return PepperedHash;
        }
        #endregion RemoveSpecialCharacters
        #region GenerateSalt
        protected string GenerateSalt()
        {
            byte[] bytes = new byte[128 / 8];
            using (var randomGenerator = RandomNumberGenerator.Create())
            {
                randomGenerator.GetBytes(bytes);
                var salt = BitConverter.ToString(bytes).Replace("-", "");
                return salt;
            }
        }
        #endregion GenerateSalt
        public abstract bool ValidatePassword(string plainInput,string hashedPassword);
        
    }
}