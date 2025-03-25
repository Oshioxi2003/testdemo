using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VNPayQRController : ControllerBase
    {
        private readonly IVnPayService _vnPayService;
        private readonly IDKHoc _IDKHoc;
        private readonly IDangkyTH03 ITin03;
        public VNPayQRController(IVnPayService vnPayService, IDKHoc iDKHoc, IDangkyTH03 _tin03 )
        {
            _vnPayService = vnPayService;
            _IDKHoc = iDKHoc;
            ITin03 = _tin03;
        }
        [HttpPost("CreatePaymentUrl")]
        public string CreatePaymentUrl(PaymentInformationModel model)
        {
            var url = _vnPayService.CreatePaymentUrl(model, HttpContext);
            return url;
            //return Redirect(url);
        }
        [HttpGet("PaymentCallback")]
        public PaymentResponseModel PaymentCallback()
        {
            var rs = _vnPayService.PaymentExecute(Request.Query);
            var Invoice_inf = rs.OrderId.Split('-');
            if (Invoice_inf.Length > 0)
            {
                if (Invoice_inf[0] == "TIN03")
                {
                    DangkyTH03 tmp = ITin03.Get(Int32.Parse(Invoice_inf[1]));
                    if (tmp != null)
                    {
                        //
                        tmp.PaymentSuccess = rs.Success;
                        tmp.PaymentMethod = rs.PaymentMethod;
                        tmp.PaymentOrderDescription = rs.OrderDescription;
                        tmp.PaymentOrderId = rs.OrderId;
                        tmp.PaymentId = rs.PaymentId;
                        
                        tmp.PaymentTransactionId = rs.TransactionId;
                        tmp.PaymentToken = rs.Token;
                        tmp.VnPayResponseCode = rs.VnPayResponseCode;
                        ITin03.Update(tmp);
                    }
                }
                else if (Invoice_inf[0] == "DKH")
                {
                    DKHoc tmp = _IDKHoc.Get(Int32.Parse(Invoice_inf[1]));
                    if (tmp != null)
                    {
                        //
                        tmp.NgayThanhtoan = DateTime.Now; 
                        //
                        tmp.PaymentSuccess = rs.Success;
                        tmp.PaymentMethod = rs.PaymentMethod;
                        tmp.PaymentOrderDescription = rs.OrderDescription;
                        tmp.PaymentId = rs.PaymentId;
                        tmp.PaymentTransactionId = rs.TransactionId;
                        tmp.PaymentToken = rs.Token;
                        tmp.VnPayResponseCode = rs.VnPayResponseCode;

                        _IDKHoc.Update(tmp);
                    }                    
                }
            }
            

            return rs;
        }
    }
}
