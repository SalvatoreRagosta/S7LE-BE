using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PizzeriaImpulsMVC.Infrastructure.Migrations
{
    public partial class IdentityDBUserV4 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "UserAccountId",
                table: "UserAddresses",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<int>(
                name: "UserAccountId",
                table: "UserAddresses",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");
        }
    }
}
