using BCrypt.Net;
using System.Net;
using AtHackers.Abstractions;

namespace AtHackers.Exceptions
{
    ///<summary> The exception thrown when the salt used in generation of the secured hash could not 
    ///be inferred from the provided stored hash password</summary>
    public class InvalidSaltException : CustomException
    {
        public InvalidSaltException(string message= @$"Invalid Salt Or 
        Password Supplied For Validation: Application Stopped With Error Code:500", HttpStatusCode statusCode = HttpStatusCode.InternalServerError) : base(message, statusCode)
        {
        }
    }
}