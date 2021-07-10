#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src
COPY ["src/Services/Victor.Cliente.API/Victor.Cliente.API.csproj", "src/Services/Victor.Cliente.API/"]
RUN dotnet restore "src/Services/Victor.Cliente.API/Victor.Cliente.API.csproj"
COPY . .
WORKDIR "/src/src/Services/Victor.Cliente.API"
RUN dotnet build "Victor.Cliente.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Victor.Cliente.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Victor.Cliente.API.dll"]