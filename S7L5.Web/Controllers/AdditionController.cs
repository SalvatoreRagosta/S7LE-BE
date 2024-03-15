using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Addition;

namespace PizzeriaImpulsMVC.Web.Controllers
{
    public class AdditionController : Controller
    {
        private readonly IAdditionService _additionService;

        public AdditionController(IAdditionService additionService)
        {
            _additionService = additionService;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            var additions = _additionService.GetAllAdditionsForList(5, 1, "");

            return View(additions);
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Index(int pageSize, int? pageNumber, string filterString)
        {
            if (!pageNumber.HasValue)
            {
                pageNumber = 1;
            }
            if(filterString is null)
            {
                filterString = String.Empty;
            }

            var additions = _additionService.GetAllAdditionsForList(pageSize, pageNumber.Value, filterString);

            return View(additions);
        }

        [HttpGet]
        [Route("addition/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddAddition()
        {
            return View(new NewAdditionVm());
        }

        [HttpPost]
        [Route("addition/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddAddition(NewAdditionVm newAdditionVm)
        {
            var id = _additionService.AddNewAddition(newAdditionVm);

            return RedirectToAction("Index");
        }

        [Authorize(Roles = "Manager")]
        public IActionResult DeleteAddition(int additionId)
        {
            _additionService.DeleteAddition(additionId);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [Authorize(Roles = "Manager")]
        public IActionResult EditAddition(int additionId)
        {
            var addition = _additionService.GetAdditionForEdit(additionId);

            return View(addition);
        }

        [HttpPost]
        [Authorize(Roles = "Manager")]
        public IActionResult EditAddition(NewAdditionVm editAdditionVm)
        {
            _additionService.EditAddition(editAdditionVm);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult GetAdditionDetails(int additionId)
        {
            var additionDetails = _additionService.GetAdditionDetails(additionId);

            return View(additionDetails);
        }
    }
}
