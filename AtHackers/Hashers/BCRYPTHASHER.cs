using System.Security.Cryptography;
using AtHackers.Exceptions;

namespace AtHackers.Hashers
{
    ///<summary>
    /// The AtHackers' class that Generates secured hashes using the Bcrypt.NET library for
    ///generation of secured hash password and also for validation.
    ///</summary>
    public class BCRYPTHASHER 
    {
        public static string GenerateHash(string Password, bool IsEnhancedBCrypt = true)
        {
           if(string.IsNullOrEmpty(Password)) throw new ValueCannotBeNullException();
           if(!IsEnhancedBCrypt) return BCrypt.Net.BCrypt.HashPassword(Password);
           else
           {
              return BCrypt.Net.BCrypt.EnhancedHashPassword(Password,11,BCrypt.Net.HashType.SHA512);
           }
        }

        
        public static bool ValidatePassword(string InputText, string HashedPassword, bool IsEnhancedBCrypt = true)
        {
            if(string.IsNullOrEmpty(InputText) || string.IsNullOrEmpty(HashedPassword)) throw new ValueCannotBeNullException();
            if(!IsEnhancedBCrypt) return BCrypt.Net.BCrypt.Verify(InputText,HashedPassword);
            return BCrypt.Net.BCrypt.EnhancedVerify(InputText,HashedPassword,BCrypt.Net.HashType.SHA512);
        }
    }
}