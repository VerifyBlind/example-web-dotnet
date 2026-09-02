# VerifyBlind .NET Example Web — Multi-stage build
# Build context: parent directory (src/)

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Restore önce — layer cache için
COPY example-web-dotnet/VerifyBlind.TestPortal.csproj example-web-dotnet/
RUN dotnet restore example-web-dotnet/VerifyBlind.TestPortal.csproj

# Kaynak kodu kopyala ve yayınla
COPY example-web-dotnet/ example-web-dotnet/

ARG LOCAL_URL_REPLACE=false
RUN if [ "$LOCAL_URL_REPLACE" = "true" ]; then \
      find /src/example-web-dotnet/wwwroot -type f \( -name "*.html" -o -name "*.js" \) \
        -exec sed -i \
          -e 's|https://cdn.verifyblind.com|http://cdn.verifyblind.localhost|g' \
          -e 's|https://api.verifyblind.com|http://api.verifyblind.localhost|g' \
          -e 's|https://partner.verifyblind.com|http://partner.verifyblind.localhost|g' \
          -e 's|https://admin.verifyblind.com|http://admin.verifyblind.localhost|g' \
          -e 's|https://test.verifyblind.com|http://test.verifyblind.localhost|g' \
          -e 's|https://app.verifyblind.com|http://app.verifyblind.localhost|g' \
          -e 's|https://verifyblind.com|http://verifyblind.localhost|g' \
          {} +; \
    fi

RUN dotnet publish example-web-dotnet/VerifyBlind.TestPortal.csproj \
    -c Release -o /publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /publish .
EXPOSE 5201
ENTRYPOINT ["dotnet", "VerifyBlind.TestPortal.dll"]
