#! /usr/bin/python 
# -*- coding: utf-8 -*-
import sys

content = '''
f12
<?xml version="1.0" encoding="utf-8"?>
<root total="100" count="1"><item id="96226" link_id="194817" subject="李某某案二审驳回上诉 维持10年原判" short_subject="李某某案二审维持10年原判" sub_subject="李某某案二审驳回上诉 维持10年原判" tag="李某案 梦鸽 二审 维持原判" source="infzm.com" author="综合" status="4" created="2013-11-27 10:28:59" modified="2013-11-27 12:02:57" publish_time="2013-11-27 11:13:39" content_type="0" template="default"><introtext><![CDATA[11月27日上午9时，北京市第一中级人民法院公开宣判上诉人李某某等五人强奸上诉一案。该院裁定驳回上诉人的上诉，维持原判。北京中院称，上诉人及辩护人提出的上诉理由及辩护意见缺乏事实及法律依据，依法不予采纳。]]></introtext><content_relations><rel_content id="96085" subject="李某某的最后陈述：“一切过错都指向我，难道就因为我是李双江的儿子？”" short_subject="“一切过错都指向我，难道就因为我是李双江的儿子？”" sub_subject="李某某的最后陈述：“一切过错都指向我，难道就因为我是李双或可减刑5年" introtext="李某某等五人强奸上诉案于19日上午9时17分，在北京市第一中级人民法院不公开开庭审理。李家辩护律师张起准表示，今天的辩护方向将主要为指出“一审判决中的错误”。" author="综合" display_time="2013-11-19 11:38:23" publish_time="2013-11-19 11:38:23" modified="2013-11-19 13:54:49" media=""/><rel_content id="94648" subject="李某某犯强奸罪被判十年 法院：不能将陪酒行为作为强奸的诱因" short_subject="李某某犯强奸罪被判十年" sub_subject="李某某犯强奸罪被判十年 法院：不能将陪酒行为作为强奸的诱因" title_subject="李某某犯强奸罪被判十年 法院：不能将陪酒行为作为强奸的诱因" introtext="法院判决李某某等五被告人强奸罪成立，李某某获刑十年，其余4人三年至十二年不等。法院的量刑意见显示，李某某在共同犯罪中属于犯意提起者、主要暴力行为实施者，地位与作用明显大于其他被告人，且无悔罪表现，鉴于其犯罪时已满十六周岁不满十八周岁，系未成年在校学生，对其依法从轻处罚。" author="综合" display_time="2013-09-26 12:56:28" publish_time="
2000
2013-09-26 12:56:28" modified="2013-09-26 13:16:51" media="2013/0926/71974.jpeg"/><rel_content id="94633" subject="李某某涉嫌强奸案8小时案情全程还原&lt;br/&gt;夜半酒吧里发生了什么" short_subject="李某某涉嫌强奸案8小时案情全程还原" sub_subject="李某某涉嫌强奸案8小时案情全程还原&lt;br/&gt;夜半酒吧里发生了什么" title_subject="李某某涉嫌强奸案8小时案情全程还原夜半酒吧里发生了什么" introtext="李某某等五人涉嫌强奸案于9月26日上午公开宣判，李某某因强奸罪一审被判有期徒刑10年。本文还原了从李某某等人进入酒吧到案发之间8个小时这一核心时间段内的过程，包括对于当事双方分别有利和不利的信息，以期尽可能接近事实。" author="南方周末记者  柴会群" display_time="2013-09-26 10:15:36" publish_time="2013-09-26 10:15:36" modified="2013-09-26 13:15:56" media="2013/0926/71970.jpeg"/><rel_content id="94027" subject="“坏人”的权利 ——从李某某案说开去" short_subject="“坏人”的权利 ——从李某某案说开去" sub_subject="“坏人”的权利 ——从李某某案说开去" title_subject="“坏人”的权利 ——从李某某案说开去" introtext="李某某案，与之前的唐慧案等一样：舆论反应激烈、一边倒地声讨“强势者”。但是，法律若不保护“坏人”的权利，“好人”的权利也很可能无法得到保障。一边倒地无限声援弱势者、声讨强势者，最具道德美感，但又不用负责任，其危害可能很严重。" author="杨俊锋（法律学者）" display_time="2013-09-06 08:56:33" publish_time="2013-09-06 08:56:33" modified="2013-09-11 11:44:57" media="2013/0905/71416.jpeg"/><rel_content id="93897" subject="李某某案庭审结束将择期宣判 5被告仅李某某不认罪" short_subject="李某某案庭审结束将择期宣判" sub_subject="李某某案庭审结束将择期宣判 5被告仅李某某不认罪" title_subject="李某某案庭审结束将择期宣判 5被告仅李某某不认罪" introtext="为期两天的李某某等5人涉嫌强奸案8月29日结束庭审，案件择期宣判。5名被告中，只有李某某是做无罪辩护。其余4名被告的辩护人做有罪辩护，3名被告或其法定代理人当庭道歉。" author="综合" display_time="2013-08-30 15:00:44" publish_time="2013-08-30 15:00:44" modified="2013-08-30 15:44:02" media="2013/0830/71264.jpeg"/><rel_content id="96217" subject="青岛中石化爆炸9人被控制" short_subject="青岛中石化爆炸9人被控制" sub_subject="青岛中石化爆炸9人被控制" title_subject="青岛中石化爆炸9人被控制" introtext="11月25日晚，警方已控制“11·22”东黄输油管道泄漏爆炸事故中石化相关人员7人、青岛经济技术开发区相关人员2人。国家安监总局局长杨栋梁对事件连发15个问题。在多年前，中石化就意识到东黄复线存在的隐患，并对部分管段进行改造。一中石化人员表示，管道漏油是经常发生的事。" author="综合" display_time="2013-11-26 13:27:04" publish_time="2013-11-26 13:27:04" modified="2013-11-26 13:33:20" media="2013/1126/74013.jpeg"/></content_relations><content_medias><media file_path="2013/1127/74036.jpeg" description="资料图片：2013年9月26日，李某某母亲梦鸽（中）在宣判后走出法院大楼。当日，北京市海淀区人民法院对被告人李某某等5人强奸一案作出一审判决，以强奸罪分别判处被告人李某某有期徒刑10年；王某（成年人）有期徒刑12年，剥夺政治权利2年；魏某某（兄）有期徒刑4年；张某某有期徒刑3年，缓刑5年；魏某某（弟）有期徒刑3年，缓刑3年。 " author="新华社记者 公磊" media_width="2048" media_height="1365"/></content_medias><fulltext><![CDATA[<div class="content_media" style="">
<p class="cm_pic_outer" style="text-align:center;"><img width="660" height="440" src="http://images.infzm.com/medias/2013/1127/74036.jpeg@660x440" class="landscape" alt="" /></p>
<p class="cm_pic_caption" style="text-align:center;color:#999;line-height:1.4em;padding:0 4em;">资料图片：2013年9月26日，李某某母亲梦鸽（中）在宣判后走出法院大楼。当日，北京市海淀区人民法院对被告人李某某等5人强奸一案作出一审判决，以强奸罪分别判处被告人李某某有期徒刑10年；王某（成年人）有期徒刑12年，剥夺政治权利2年；魏某某（兄）有期徒刑4年；张某某有期徒刑3年，缓刑5年；魏某某（弟）有期徒刑3年，缓刑3年。 <span class="cm_pic_author" style="color:#AAA;">（新华社记者 公磊/图）</span></p>
</div>
<p>据北京市第一中级人民法院<a target="_blank" href="http://e.weibo.com/3820915614/AkDIbDbLW">官方微博</a>消息，11月27日上午9时，北京市第一中级人民法院公开宣判上诉人李某某等五人强奸上诉一案。该院裁定驳回上诉人的上诉，维持原判。</p>
<p>合议庭审查了全案卷宗材料，对一审判决中所列举的认定李某某等五人犯强奸罪的证据经审核予以确认，认为审判决书认定的事实清楚，证据确实、充分，依法作出了二审裁判。</p>
<p>北京中院认为,上诉人李某某、王某及原审被告人魏某某(兄)、张某某、魏某某(弟)违背妇女意志，采用暴力手段，强行与妇女发生性关系。严重侵犯了妇女的人身权利，其行为均已构成强奸罪。且系轮奸，依法均应惩处。</p>
<p>一审法院围绕李某某等五人是否与被害人发生了性关系、是否对被害人实施了暴力行为，与被害人意愿等与犯罪事实密切相关的问题进行了严格的审的基础上，综台五人明确具体且相互印证的有罪供述及被害人陈述、证人证言、物证鉴定意见，能够排除合理怀疑。  审法院根据李某某等五人其同实施强奸犯罪的事实、性质及对于社会的危害程度，综台考虑全案情况及李某某等五人的具体犯罪情节，根据宽严相济的刑事政策。本着有利于末成年罪犯的教育和矫正原则，作出的刑事判决认定事实清楚，证据确实、充分，定罪及适用法律正确。量刑适当，审判程序合法，应予维持。</p>
<p>北京中院称，上诉人及辩护人提出的事实不清、证据不足、量刑过重等上诉理由及辩护意见。缺乏事实及法律依据，依法不予采纳。</p>
<p>另据北京市第一中级人民法院透露<a href="http://e.weibo.com/3820915614/AkDC1h3S7" target="_blank">消息</a>，宣判结束后，合议庭结合审判情况及判决结果，对未成年上诉人和原审被告人进行了法庭教育。</p>
<h3 class="thirdTitle" style="">李某某、王某坚持无罪辩护</h3>
<p>据<a target="_blank" href="http://news.xinhuanet.com/legal/2013-11/27/c_125768176.htm">新华网</a>报道，该案二审11月19日在北京一中院依法进行不公开开庭审理。上诉人李某某的辩护人坚持无罪辩护，上诉人李某某和上诉人梦鸽表示同意辩护人意见。</p>
<p>据《<a target="_blank" href="http://www.infzm.com/content/96085">南方周末</a>》此前报道，李某某在二审时当庭宣读了由其本人所写、长达10分钟的&ldquo;最后陈述&rdquo;，并三次鞠躬。</p>
<p>他称，&ldquo;一切的过错都指向了我。难道就因为我是李双江的儿子吗？如果我为了少判几年，就承认我没有做的事情，我对不起我的父母，对不起家族的荣誉。承认我没有干的事情难道就叫做态度好吗？&rdquo;</p>
<p>李某某在最后陈述时还说，妈妈的每次来信都教育他要做好人，不要恨别人，要学会宽容。他也是按照妈妈的话去思考去做的。他不恨所有的人，并感谢老师这些年的教育，感谢父母的教育和培养。</p>
<p>他称，后悔知道有人要去做坏事时没有制止，还跟着去，父母只有自己一个孩子，希望法官、检察官都换位思考。&ldquo;我不承认犯
943
罪并不是对抗法律，我的母亲和律师也不是对抗法律。目前没有证据证明我犯罪，请法官慎重裁判。&rdquo;李某某表示。&ldquo;最后，我再次对因为我的事情受到牵连的这样多人，说句对不起！给你们添麻烦了！&rdquo;</p>
<p>据前述新华网报道，除李某某，上诉人王某的辩护人同样坚持无罪辩护，上诉人王某表示同意辩护人意见。</p>
<p>而其余3名原审被告人均当庭表示坚持一审庭审时的供述意见。除1名原审被告人的辩护人请求法庭予以改判、宣告缓刑外，其余2名原审被告人的辩护人均对一审判决结果不持异议。被害人的诉讼代理人表示，认可一审判决，建议二审维持原判。</p>
<p>据<a target="_blank" href="http://china.cnr.cn/ygxw/201311/t20131127_514248665.shtml">中广网</a>报道，在整个案件报道过程中，李某某的代理律师也曾提到如果二审维持一审判决，依然判决李某某有罪的话，李某某的监护人有可能还要进行申诉。但是按照我们国家的刑事诉讼法的规定，刑事案件是二审终审制，但是如果上诉人有新的情况还要继续申诉的，法律也是维护权利。</p>
<div class="bgInformation" style="color:#333;display:block;padding:8px;border-radius:1px;border:1px solid #CCC;font-weight:700;">
<p>李某某案</p>
<p>2013年2月17日凌晨，5名被告人以殴打、恐吓方式强行带被害人杨某某到达北京海淀区的一酒店内，杨某某被李某某等人要求脱下衣服，其拒绝后遭李某某、王某等人扇打、踢踹并被强行脱光衣服。李某某、王某、魏某某（兄）、张某某、魏某某（弟）依次强行与杨某某发生性关系。后李某某、魏某某（兄）拿出人民币2000元给杨某某。</p>
<p>北京市海淀区法院9月26日对李某某等五人强奸案作出一审判决，以强奸罪分别判处李某某有期徒刑10年；王某（成年人）有期徒刑12年，剥夺政治权利2年；魏某某（兄）有期徒刑4年；张某某有期徒刑3年，缓刑5年；魏某某（弟）有期徒刑3年，缓刑3年。</p>
<p>来源：新华网</p>
</div>
<p>&nbsp;</p>]]></fulltext><snsShare url="http://www.infzm.com/content/96226" sina="6" qqweibo="4" sinaurl="http://t.cn/8kyAT3x"/></item></root>

0


'''
print len(content)

def decode_chunked(content):
    content = content.lstrip('\r') 
    content = content.lstrip('\n')
    temp = content.find('\r\n')
    strtemp = content[0:temp]
    readbytes = int(strtemp, 16)
    newcont = ''
    start = 2
    offset = temp + 2
    newcont = ''
    while(readbytes > 0):
        newcont += content[offset:readbytes + offset]
        offset += readbytes
        endtemp = content.find('\r\n', offset + 2)
        if(endtemp > -1):
            strtemp = content[offset + 2:endtemp]
            readbytes = int(strtemp, 16)
            if(readbytes == 0): 
                break
            else:
                offset = endtemp + 2
    
    content = newcont
    return content

decode_chunked(content)
sys.exit(0)

def _parse_chunked_data(content):
        print "_parse_chunked_data: "
        print "[%s]" % content
        print len(content)

        result = ''
        cur = 0
        while True:
            index = content.find("\r\n", cur)
            if(index < 0):
                print "Index < 0"
                break
            print "Cur %d, Index %d" % (cur, index)
            print "Char: %s" % content[cur:index]
            size = int(content[cur:index], 16)
            print "Size=%d" % size
            if size == 0: break
            print "Part: [%s]" % content[index + 2: index + 2 + size]
            result += content[index + 2: index + 2 + size]
            cur = index + 2 + size + 1
        print result
        return result


_parse_chunked_data(content)
