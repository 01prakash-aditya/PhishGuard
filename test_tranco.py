import asyncio
from backend.main import analyze_cloud, AnalysisRequest, startup_event

async def test():
    startup_event()
    req1 = AnalysisRequest(url="https://www.point72.com/careers/", htmlExcerpt="")
    res1 = await analyze_cloud(req1)
    print("POINT72:", res1)
    
    req2 = AnalysisRequest(url="https://www.random-phishing-site-99.xyz/login", htmlExcerpt="")
    res2 = await analyze_cloud(req2)
    print("PHISH:", res2)

asyncio.run(test())
