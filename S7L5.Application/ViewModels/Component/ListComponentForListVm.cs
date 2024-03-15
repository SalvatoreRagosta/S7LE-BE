namespace PizzeriaImpulsMVC.Application.ViewModels.Component
{
    public class ListComponentForListVm
    {
        public List<ComponentForListVm>? Components { get; set; }
        public int CurrentPage { get; set; }
        public int PageSize { get; set; }
        public string FilterString { get; set; }
        public int Count { get; set; }
    }
}
